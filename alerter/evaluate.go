package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// metricDef describes how a rule's metric is read. Gauges use
// last_over_time to bridge the gap between pushes; counters (disk busy time)
// use rate. max by (host_id) folds per-disk, per-mount and per-core series
// into "the worst one on this host".
type metricDef struct {
	name    string
	matcher string // extra fixed label matcher, if any
	rate    bool   // a counter of seconds, shown as percent busy
	label   string // human name for messages
	unit    string
}

var alertMetrics = map[string]metricDef{
	"cpu":       {name: "pulsegrid_cpu_usage_percent", label: "CPU usage", unit: "%"},
	"memory":    {name: "pulsegrid_memory_used_percent", label: "Memory usage", unit: "%"},
	"swap":      {name: "pulsegrid_swap_used_percent", label: "Swap usage", unit: "%"},
	"disk":      {name: "pulsegrid_disk_used_percent", label: "Disk usage", unit: "%"},
	"load1":     {name: "pulsegrid_load", matcher: `period="1m"`, label: "Load (1m)"},
	"load5":     {name: "pulsegrid_load", matcher: `period="5m"`, label: "Load (5m)"},
	"iowait":    {name: "pulsegrid_cpu_mode_percent", matcher: `mode="iowait"`, label: "CPU iowait", unit: "%"},
	"steal":     {name: "pulsegrid_cpu_mode_percent", matcher: `mode="steal"`, label: "CPU steal", unit: "%"},
	"inodes":    {name: "pulsegrid_disk_inodes_used_percent", label: "Inode usage", unit: "%"},
	"disk_busy": {name: "pulsegrid_disk_io_time_seconds_total", rate: true, label: "Disk busy time", unit: "%"},
}

// Process and service rules read what the agent reports for the names it
// was told to watch (via its config): a count of matching processes, and 1
// or 0 for a service. Both breach below 1.
var targetMetrics = map[string]struct{ name, label string }{
	"process_down": {"pulsegrid_watched_process_count", "process"},
	"service_down": {"pulsegrid_service_up", "service"},
}

// A host whose dependency has been silent this long has its alerts held
// back: with the gateway or hypervisor down, its own silence says nothing.
// It must be shorter than the shortest host_down rule (60s, see the API's
// MIN_HOST_DOWN_SECONDS), or when both go quiet together the dependent host's
// alert fires before its parent counts as down. Erring short only delays
// alerts (they're held at pending), it never sends one.
const parentSilentAfter = 45 * time.Second

const lastSeenKey = "pg:last_seen:" // shared with ingest/cache.go and api heartbeats.py

type evaluator struct {
	store     *store
	vmURL     string
	http      *http.Client
	rdb       *redis.Client
	log       *slog.Logger
	baseURL   string // PUBLIC_DASHBOARD_URL, for links in messages
	apiURL    string // PUBLIC_API_URL, for one-click acknowledge links
	ackSecret string // ACK_SIGNING_SECRET, shared with the API
}

// cycle caches per-tenant lookups for one evaluation pass.
type cycle struct {
	windows map[string][]window
}

func (e *evaluator) maintenanceFor(ctx context.Context, c *cycle, tenantID string) []window {
	if w, ok := c.windows[tenantID]; ok {
		return w
	}
	w, err := e.store.maintenance(ctx, tenantID)
	if err != nil {
		// Without the windows, alert as usual rather than not at all.
		e.log.Error("loading maintenance windows", "tenant_id", tenantID, "err", err)
	}
	c.windows[tenantID] = w
	return w
}

func (e *evaluator) evaluateAll(ctx context.Context, partition, partitions int) {
	rules, err := e.store.rules(ctx, partition, partitions)
	if err != nil {
		e.log.Error("loading rules", "err", err)
		return
	}
	c := &cycle{windows: map[string][]window{}}
	for _, r := range rules {
		if ctx.Err() != nil {
			return
		}
		if err := e.evaluate(ctx, c, r); err != nil {
			e.log.Error("evaluating rule", "rule_id", r.ID, "tenant_id", r.TenantID, "err", err)
		}
	}
	e.escalateAll(ctx, c, partition, partitions)
}

func (e *evaluator) evaluate(ctx context.Context, c *cycle, r rule) error {
	hosts, err := e.store.hosts(ctx, r)
	if err != nil || len(hosts) == 0 {
		return err
	}
	states, err := e.store.states(ctx, r.ID)
	if err != nil {
		return err
	}

	var obs map[string]observation
	duration := time.Duration(r.DurationSeconds) * time.Second
	switch r.Kind {
	case "metric", "process_down", "service_down":
		obs, err = e.metricObservations(ctx, r)
	case "host_down":
		obs, err = e.hostDownObservations(ctx, r, hosts)
		// Silence for duration_seconds is itself the condition, already
		// measured, so fire as soon as it's observed.
		duration = 0
	default:
		return fmt.Errorf("unknown rule kind %q", r.Kind)
	}
	if err != nil {
		return err
	}

	parentDown, err := e.silentParents(ctx, hosts)
	if err != nil {
		return err
	}
	windows := e.maintenanceFor(ctx, c, r.TenantID)
	now := time.Now()
	for _, h := range hosts {
		prev := states[h.ID]
		o := obs[h.ID]
		next, act := transition(prev.alertState, o, duration, now)
		suppressed := inMaintenance(windows, h, now) || (h.DependsOn != nil && parentDown[*h.DependsOn])
		if suppressed && act == actionOpen {
			// Hold at pending, keeping when the breach began, so it fires
			// right after the window if it's still going on.
			since := now
			if prev.State == statePending {
				since = prev.Since
			}
			next, act = alertState{State: statePending, Since: since}, actionNone
		}
		if next == prev.alertState && act == actionNone {
			continue
		}
		msg := func(kind, incidentID string) message { return e.message(r, h, o, kind, incidentID) }
		quiet := suppressed && act == actionResolve
		if err := e.store.apply(ctx, r, h, prev, next, act, o.Value, quiet, msg); err != nil {
			return err
		}
		if act != actionNone {
			e.log.Info("alert transition", "rule_id", r.ID, "host", h.Hostname,
				"state", next.State, "value", o.Value, "tenant_id", r.TenantID)
		}
	}
	return nil
}

// ruleQuery builds the MetricsQL for a metric, process or service rule.
func ruleQuery(r rule) (string, error) {
	var matchers []string
	if r.HostID != nil {
		matchers = append(matchers, fmt.Sprintf("host_id=%q", *r.HostID))
	}
	if t, ok := targetMetrics[r.Kind]; ok {
		// strconv.Quote escapes like PromQL's double-quoted strings.
		matchers = append([]string{t.label + "=" + strconv.Quote(r.Target)}, matchers...)
		return fmt.Sprintf("max by (host_id) (last_over_time(%s{%s}[3m]))", t.name, strings.Join(matchers, ",")), nil
	}
	def, ok := alertMetrics[r.Metric]
	if !ok {
		return "", fmt.Errorf("unknown metric %q", r.Metric)
	}
	if def.matcher != "" {
		matchers = append([]string{def.matcher}, matchers...)
	}
	sel := def.name + "{" + strings.Join(matchers, ",") + "}"
	if def.rate {
		return fmt.Sprintf("max by (host_id) (rate(%s[3m])) * 100", sel), nil
	}
	return fmt.Sprintf("max by (host_id) (last_over_time(%s[3m]))", sel), nil
}

func (e *evaluator) metricObservations(ctx context.Context, r rule) (map[string]observation, error) {
	query, err := ruleQuery(r)
	if err != nil {
		return nil, err
	}

	params := url.Values{
		"query": {query},
		// Same guard as the API: VictoriaMetrics adds this to every selector.
		"extra_label": {"tenant_id=" + r.TenantID},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.vmURL+"/api/v1/query?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := e.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("victoriametrics query: %s", resp.Status)
	}
	var body struct {
		Data struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Value  [2]any            `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	out := map[string]observation{}
	for _, res := range body.Data.Result {
		s, _ := res.Value[1].(string)
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			continue
		}
		hit := breached(r.Operator, v, r.Threshold)
		if _, ok := targetMetrics[r.Kind]; ok {
			hit = v < 1
		}
		out[res.Metric["host_id"]] = observation{HasData: true, Breached: hit, Value: v}
	}
	return out, nil
}

// silentParents reports, for each host that others depend on, whether it has
// been silent for parentSilentAfter. A parent that has never reported isn't
// counted as down: there's nothing to say it was ever up.
func (e *evaluator) silentParents(ctx context.Context, hosts []host) (map[string]bool, error) {
	var ids []string
	seen := map[string]bool{}
	for _, h := range hosts {
		if h.DependsOn != nil && !seen[*h.DependsOn] {
			seen[*h.DependsOn] = true
			ids = append(ids, *h.DependsOn)
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = lastSeenKey + id
	}
	vals, err := e.rdb.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for i, id := range ids {
		if s, ok := vals[i].(string); ok {
			if ts, err := strconv.ParseInt(s, 10, 64); err == nil {
				out[id] = time.Since(time.Unix(ts, 0)) >= parentSilentAfter
			}
		}
	}
	return out, nil
}

func (e *evaluator) hostDownObservations(ctx context.Context, r rule, hosts []host) (map[string]observation, error) {
	keys := make([]string, len(hosts))
	for i, h := range hosts {
		keys[i] = lastSeenKey + h.ID
	}
	vals, err := e.rdb.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	limit := time.Duration(r.DurationSeconds) * time.Second
	out := map[string]observation{}
	for i, h := range hosts {
		var last time.Time
		if s, ok := vals[i].(string); ok {
			if ts, err := strconv.ParseInt(s, 10, 64); err == nil {
				last = time.Unix(ts, 0)
			}
		}
		if last.IsZero() {
			// Never reported (or the heartbeat expired): count from when the
			// host was registered, so a fresh install gets time to start.
			last = h.CreatedAt
		}
		silent := now.Sub(last)
		out[h.ID] = observation{HasData: true, Breached: silent >= limit, Value: silent.Seconds()}
	}
	return out, nil
}

func (e *evaluator) message(r rule, h host, o observation, kind, incidentID string) message {
	var condition, subject string
	resolved := kind == "alert_resolved"
	switch r.Kind {
	case "host_down":
		condition = fmt.Sprintf("no data for %s", time.Duration(o.Value*float64(time.Second)).Round(time.Second))
		subject = fmt.Sprintf("%s is not reporting", h.Hostname)
		if resolved {
			subject = fmt.Sprintf("%s is reporting again", h.Hostname)
		}
	case "process_down":
		condition = fmt.Sprintf("%s: %d processes running", r.Target, int(o.Value))
		subject = fmt.Sprintf("Process %s is not running on %s", r.Target, h.Hostname)
		if resolved {
			subject = fmt.Sprintf("Process %s is running again on %s", r.Target, h.Hostname)
		}
	case "service_down":
		state := "stopped"
		if o.Value >= 1 {
			state = "running"
		}
		condition = fmt.Sprintf("Service %s is %s", r.Target, state)
		subject = fmt.Sprintf("Service %s is down on %s", r.Target, h.Hostname)
		if resolved {
			subject = fmt.Sprintf("Service %s is running again on %s", r.Target, h.Hostname)
		}
	default:
		def := alertMetrics[r.Metric]
		condition = fmt.Sprintf("%s is %.1f%s (threshold %s %g%s)", def.label, o.Value, def.unit, r.Operator, r.Threshold, def.unit)
		subject = fmt.Sprintf("%s on %s", r.Name, h.Hostname)
	}
	state := "FIRING"
	if resolved {
		state = "RESOLVED"
	}
	text := fmt.Sprintf("%s: %s\n\nHost: %s\nRule: %s\n%s\nTime: %s\n",
		state, subject, h.Hostname, r.Name, condition, time.Now().UTC().Format(time.RFC1123))
	text += e.links(incidentID, !resolved)
	return message{
		Subject: fmt.Sprintf("[Pulsegrid] %s: %s", state, subject),
		Text:    text,
		Event: map[string]any{
			"type":        kind,
			"summary":     subject,
			"incident_id": incidentID,
			"rule_id":     r.ID,
			"rule_name":   r.Name,
			"host_id":     h.ID,
			"hostname":    h.Hostname,
			"value":       o.Value,
			"metric":      r.Metric,
			"kind":        r.Kind,
			"target":      r.Target,
		},
	}
}

// links adds the incident's dashboard link and, while it's open, the
// one-click acknowledge link.
func (e *evaluator) links(incidentID string, withAck bool) string {
	var out string
	if link := dashboardLink(e.baseURL, incidentID); link != "" {
		out += fmt.Sprintf("\nDetails: %s\n", link)
	}
	if withAck {
		if link := ackURL(e.apiURL, e.ackSecret, incidentID); link != "" {
			out += fmt.Sprintf("Acknowledge (stops escalation): %s\n", link)
		}
	}
	return out
}

// dashboardLink points at the incident in the dashboard. The console's URL
// carries the tab in its query string (/monitoring?tab=servers); a
// standalone dashboard uses a path.
func dashboardLink(base, incidentID string) string {
	if base == "" || incidentID == "" {
		return ""
	}
	if strings.Contains(base, "?") {
		return base + "&section=alerts&incident=" + url.QueryEscape(incidentID)
	}
	return strings.TrimRight(base, "/") + "/incidents/" + incidentID
}

// escalateAll runs the due escalation steps of open, unacknowledged
// incidents. A host in maintenance waits until the window ends.
func (e *evaluator) escalateAll(ctx context.Context, c *cycle, partition, partitions int) {
	due, err := e.store.dueEscalations(ctx, partition, partitions)
	if err != nil {
		e.log.Error("loading escalations", "err", err)
		return
	}
	now := time.Now()
	for _, esc := range due {
		if esc.HostID != nil {
			h, err := e.store.host(ctx, esc.TenantID, *esc.HostID)
			if err == nil && inMaintenance(e.maintenanceFor(ctx, c, esc.TenantID), h, now) {
				continue
			}
		}
		payload, err := json.Marshal(e.escalationMessage(esc, now))
		if err != nil {
			continue
		}
		sent, err := e.store.escalate(ctx, esc, payload)
		if err != nil {
			e.log.Error("escalating", "incident_id", esc.IncidentID, "err", err)
			continue
		}
		if sent {
			e.log.Info("incident escalated", "incident_id", esc.IncidentID, "step", esc.Level+1,
				"tenant_id", esc.TenantID)
		}
	}
}

func (e *evaluator) escalationMessage(esc escalation, now time.Time) message {
	open := now.Sub(esc.OpenedAt).Round(time.Minute)
	text := fmt.Sprintf("ESCALATED: %s\n\nNobody has acknowledged this alert for %s.\n"+
		"Host: %s\nRule: %s\nOpened: %s\nEscalation step %d of %d\n",
		esc.Summary, open, esc.Hostname, esc.RuleName, esc.OpenedAt.UTC().Format(time.RFC1123), esc.Level+1, esc.Steps)
	text += e.links(esc.IncidentID, true)
	return message{
		Subject: fmt.Sprintf("[Pulsegrid] ESCALATED: %s (unacknowledged %s)", esc.Summary, open),
		Text:    text,
		Event: map[string]any{
			"type":        "alert_escalation",
			"summary":     esc.Summary,
			"incident_id": esc.IncidentID,
			"rule_name":   esc.RuleName,
			"hostname":    esc.Hostname,
			"step":        esc.Level + 1,
		},
	}
}
