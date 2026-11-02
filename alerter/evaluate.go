package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

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
	vlogsURL  string // VICTORIALOGS_URL; empty: log rules don't evaluate
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
	hosts, err := e.subjects(ctx, r)
	if err != nil || len(hosts) == 0 {
		return err
	}
	states, err := e.store.states(ctx, r.ID)
	if err != nil {
		return err
	}

	var obs map[string]observation
	duration := time.Duration(r.DurationSeconds) * time.Second
	switch {
	case r.Kind == "host_down":
		obs, err = e.hostDownObservations(ctx, r, hosts)
		// Silence for duration_seconds is itself the condition, already
		// measured, so fire as soon as it's observed.
		duration = 0
	case r.Kind == "check" && r.Check != nil && r.Check.OnProbes:
		obs, err = e.probeCheckObservations(ctx, r)
	case r.Kind == "logs":
		obs, err = e.logObservations(ctx, r, hosts)
	default:
		obs, err = e.metricObservations(ctx, r)
	}
	if err != nil {
		return err
	}

	parentDown, err := e.silentParents(ctx, hosts)
	if err != nil {
		return err
	}
	// One problem, one alert: while a host is silent, its other rules hold
	// back (the "not reporting" alert covers it). Uptime checks run by the
	// probes don't depend on any host.
	var silent map[string]bool
	if r.Kind != "host_down" && !(r.Check != nil && r.Check.OnProbes) {
		if silent, err = e.silentHosts(ctx, hosts); err != nil {
			return err
		}
	}
	windows := e.maintenanceFor(ctx, c, r.TenantID)
	now := time.Now()
	for _, h := range hosts {
		prev := states[h.ID]
		o := obs[h.ID]
		// Hysteresis: once firing, stay firing until the value is back past
		// the recovery threshold, not merely back under the alert threshold.
		if prev.State == stateFiring && o.HasData && r.RecoveryThreshold != nil {
			o.Breached = breached(r.Operator, o.Value, *r.RecoveryThreshold)
		}
		next, act := transition(prev.alertState, o, duration, now)
		suppressed := (!h.IsCheck && inMaintenance(windows, h, now)) ||
			(h.DependsOn != nil && parentDown[*h.DependsOn]) || silent[h.ID]
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
		if act != actionNone {
			o.Detail = e.checkDetail(ctx, r, h)
			if r.Kind == "plugin_down" {
				o.Plugins, o.Detail = e.pluginDetail(ctx, r, h, act)
			}
		}
		msg := func(kind, incidentID string) message { return e.message(r, h, o, kind, incidentID) }
		quiet := suppressed && act == actionResolve
		if err := e.store.apply(ctx, r, h, prev, next, act, o, quiet, msg); err != nil {
			return err
		}
		if act != actionNone {
			e.log.Info("alert transition", "rule_id", r.ID, "subject", h.Hostname,
				"state", next.State, "value", o.Value, "tenant_id", r.TenantID)
		}
	}
	return nil
}

// subjects are what a rule is evaluated for: its hosts, the hosts a
// host-run check covers, or for a probe-run uptime check, the check itself.
func (e *evaluator) subjects(ctx context.Context, r rule) ([]host, error) {
	if r.Kind != "check" {
		return e.store.hosts(ctx, r)
	}
	if r.Check == nil {
		return nil, nil // the check was deleted; the rule goes with it
	}
	if r.Check.OnProbes {
		return []host{{ID: r.Check.ID, Hostname: r.Check.Name, IsCheck: true, CreatedAt: r.Check.CreatedAt}}, nil
	}
	scoped := r
	scoped.HostID, scoped.Tag = r.Check.HostID, r.Check.Tag
	return e.store.hosts(ctx, scoped)
}

// silentHosts reports hosts that haven't pushed for parentSilentAfter.
func (e *evaluator) silentHosts(ctx context.Context, hosts []host) (map[string]bool, error) {
	keys := make([]string, len(hosts))
	for i, h := range hosts {
		keys[i] = lastSeenKey + h.ID
	}
	vals, err := e.rdb.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for i, h := range hosts {
		if s, ok := vals[i].(string); ok {
			if ts, err := strconv.ParseInt(s, 10, 64); err == nil {
				out[h.ID] = time.Since(time.Unix(ts, 0)) >= parentSilentAfter
			}
		}
	}
	return out, nil
}

// probeCheckObservations: an uptime check is down when at least
// min_failing probe locations (capped at how many report) see it failing.
func (e *evaluator) probeCheckObservations(ctx context.Context, r rule) (map[string]observation, error) {
	fq, tq := probeCheckQuery(r.Check.ID)
	failing, err := e.queryScalar(ctx, r.TenantID, fq)
	if err != nil {
		return nil, err
	}
	total, err := e.queryScalar(ctx, r.TenantID, tq)
	if err != nil {
		return nil, err
	}
	if total == nil {
		return map[string]observation{}, nil // no probe has reported yet
	}
	need := float64(r.Check.MinFailing)
	if need > *total {
		need = *total
	}
	if need < 1 {
		need = 1
	}
	f := 0.0
	if failing != nil {
		f = *failing
	}
	return map[string]observation{r.Check.ID: {HasData: true, Breached: f >= need, Value: f, Total: *total}}, nil
}

// checkDetail is the result text for a check rule's subject, from what
// ingest stored: the host's latest failure (kept apart because a passing
// run may already have replaced the current result), or for an uptime
// check, every failing probe's.
func (e *evaluator) checkDetail(ctx context.Context, r rule, h host) string {
	if r.Kind != "check" || r.Check == nil {
		return ""
	}
	vals, err := e.rdb.HGetAll(ctx, checkResultKey+r.Check.ID).Result()
	if err != nil {
		return ""
	}
	type result struct {
		OK        bool   `json:"ok"`
		Detail    string `json:"detail"`
		Region    string `json:"region"`
		Ts        int64  `json:"ts"`
		Diagnosis *struct {
			Summary string `json:"summary"`
		} `json:"diagnosis"`
	}
	// The agent's diagnosis says where it breaks: DNS, connect, path. It
	// comes with one failing run; ingest keeps the latest under diag:<place>.
	diagnosisOf := func(field string, res result) string {
		if res.Diagnosis != nil && res.Diagnosis.Summary != "" {
			return res.Diagnosis.Summary
		}
		var stored struct {
			Ts        int64 `json:"ts"`
			Diagnosis *struct {
				Summary string `json:"summary"`
			} `json:"diagnosis"`
		}
		if json.Unmarshal([]byte(vals["diag:"+field]), &stored) == nil && stored.Diagnosis != nil &&
			res.Ts-stored.Ts < (30*time.Minute).Milliseconds() {
			return stored.Diagnosis.Summary
		}
		return ""
	}
	withDiagnosis := func(field string, res result) string {
		if d := diagnosisOf(field, res); d != "" {
			return res.Detail + " (" + d + ")"
		}
		return res.Detail
	}
	recent := func(res result) bool { return time.Since(time.UnixMilli(res.Ts)) < 10*time.Minute }
	if !r.Check.OnProbes {
		var cur, fail result
		json.Unmarshal([]byte(vals[h.ID]), &cur)
		if json.Unmarshal([]byte(vals["fail:"+h.ID]), &fail) == nil && recent(fail) && (cur.OK || fail.Ts >= cur.Ts) {
			return withDiagnosis(h.ID, fail)
		}
		return withDiagnosis(h.ID, cur)
	}
	var parts []string
	for field, v := range vals {
		if strings.HasPrefix(field, "fail:") || strings.HasPrefix(field, "diag:") {
			continue
		}
		var res result
		if json.Unmarshal([]byte(v), &res) == nil && !res.OK {
			parts = append(parts, res.Region+": "+withDiagnosis(field, res))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

const checkResultKey = "pg:check:" // shared with ingest/cache.go

func (e *evaluator) metricObservations(ctx context.Context, r rule) (map[string]observation, error) {
	query, err := ruleQuery(r)
	if err != nil {
		return nil, err
	}
	results, err := e.queryVector(ctx, r.TenantID, query)
	if err != nil {
		return nil, err
	}
	out := map[string]observation{}
	for hostID, v := range results {
		var hit bool
		switch r.Kind {
		case "anomaly":
			hit = v > r.Threshold
		case "forecast":
			// Predicted to reach 100% (95% for memory, where the OOM killer
			// steps in first) within the horizon.
			limit := 100.0
			if r.Metric == "memory" {
				limit = 95
			}
			hit = v >= limit
		default:
			if _, ok := targetMetrics[r.Kind]; ok {
				hit = v < 1
			} else {
				hit = breached(r.Operator, v, r.Threshold)
			}
		}
		out[hostID] = observation{HasData: true, Breached: hit, Value: v}
	}
	return out, nil
}

// queryVector runs an instant query for one tenant and returns the value per
// host_id. extra_label is the same guard as the API's: VictoriaMetrics adds
// it to every selector, so a rule only ever sees its own tenant's series.
func (e *evaluator) queryVector(ctx context.Context, tenantID, query string) (map[string]float64, error) {
	params := url.Values{"query": {query}, "extra_label": {"tenant_id=" + tenantID}}
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
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return nil, fmt.Errorf("victoriametrics query: %s: %s", resp.Status, b)
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
	out := map[string]float64{}
	for _, res := range body.Data.Result {
		s, _ := res.Value[1].(string)
		v, err := strconv.ParseFloat(s, 64)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		out[res.Metric["host_id"]] = v
	}
	return out, nil
}

// queryScalar runs a query that yields a single series without labels.
func (e *evaluator) queryScalar(ctx context.Context, tenantID, query string) (*float64, error) {
	res, err := e.queryVector(ctx, tenantID, query)
	if err != nil {
		return nil, err
	}
	if v, ok := res[""]; ok {
		return &v, nil
	}
	return nil, nil
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
	resolved := kind == "alert_resolved"
	subject, condition := describe(r, h, o, resolved)
	state := "FIRING"
	if resolved {
		state = "RESOLVED"
	}
	where := "Host"
	if h.IsCheck {
		where = "Check"
	}
	text := fmt.Sprintf("%s: %s\n\n%s: %s\nRule: %s\nSeverity: %s\n%s\n",
		state, subject, where, h.Hostname, r.Name, r.Severity, condition)
	if o.Detail != "" {
		text += "Detail: " + o.Detail + "\n"
	}
	if r.Description != "" && !resolved {
		text += "\n" + r.Description + "\n"
	}
	text += fmt.Sprintf("Time: %s\n", time.Now().UTC().Format(time.RFC1123))
	text += e.links(incidentID, !resolved)
	return message{
		Subject: fmt.Sprintf("[Pulsegrid] %s: %s", state, subject),
		Text:    text,
		Event: map[string]any{
			"type":        kind,
			"summary":     subject,
			"condition":   condition,
			"detail":      o.Detail,
			"severity":    r.Severity,
			"incident_id": incidentID,
			"rule_id":     r.ID,
			"rule_name":   r.Name,
			"host_id":     h.ID,
			"hostname":    h.Hostname,
			"value":       o.Value,
			"metric":      r.Metric,
			"kind":        r.Kind,
			"target":      r.Target,
			"url":         dashboardLink(e.baseURL, incidentID),
		},
	}
}

// describe returns a message's subject line and the condition it reports.
func describe(r rule, h host, o observation, resolved bool) (subject, condition string) {
	pick := func(firing, ok string) string {
		if resolved {
			return ok
		}
		return firing
	}
	switch r.Kind {
	case "host_down":
		condition = fmt.Sprintf("No data for %s", time.Duration(o.Value*float64(time.Second)).Round(time.Second))
		subject = pick(h.Hostname+" is not reporting", h.Hostname+" is reporting again")
	case "process_down":
		condition = fmt.Sprintf("%s: %d processes running", r.Target, int(o.Value))
		subject = pick(fmt.Sprintf("Process %s is not running on %s", r.Target, h.Hostname),
			fmt.Sprintf("Process %s is running again on %s", r.Target, h.Hostname))
	case "service_down":
		condition = fmt.Sprintf("Service %s is %s", r.Target, map[bool]string{true: "running", false: "stopped"}[o.Value >= 1])
		subject = pick(fmt.Sprintf("Service %s is down on %s", r.Target, h.Hostname),
			fmt.Sprintf("Service %s is running again on %s", r.Target, h.Hostname))
	case "plugin_down":
		name := r.Target
		switch {
		case name != "":
			name = "Plugin " + name
		case o.Plugins != "":
			name = "Plugin " + o.Plugins
		default:
			name = "A plugin"
		}
		condition = fmt.Sprintf("%s can't collect metrics", name)
		subject = pick(fmt.Sprintf("%s is failing on %s", name, h.Hostname),
			fmt.Sprintf("%s is working again on %s", name, h.Hostname))
	case "container_down":
		condition = fmt.Sprintf("Container %s is %s", r.Target, map[bool]string{true: "running", false: "not running"}[o.Value >= 1])
		subject = pick(fmt.Sprintf("Container %s is down on %s", r.Target, h.Hostname),
			fmt.Sprintf("Container %s is running again on %s", r.Target, h.Hostname))
	case "check":
		name := r.Name
		if r.Check != nil {
			name = r.Check.Name
		}
		if h.IsCheck {
			condition = fmt.Sprintf("Failing from %d of %d locations", int(o.Value), int(o.Total))
			subject = pick(name+" is down", name+" is up again")
		} else {
			condition = "Check " + pick("failing", "passing")
			subject = pick(fmt.Sprintf("%s is failing on %s", name, h.Hostname),
				fmt.Sprintf("%s is passing again on %s", name, h.Hostname))
		}
	case "anomaly":
		def := alertMetrics[r.Metric]
		condition = fmt.Sprintf("%s is %.1f standard deviations above its usual level for the past week", def.label, o.Value)
		subject = pick(fmt.Sprintf("Unusual %s on %s", strings.ToLower(def.label), h.Hostname),
			fmt.Sprintf("%s is back to normal on %s", def.label, h.Hostname))
	case "forecast":
		def := alertMetrics[r.Metric]
		condition = fmt.Sprintf("At the current rate, %s reaches %.0f%s within %g hours", strings.ToLower(def.label), o.Value, def.unit, r.Threshold)
		what := map[string]string{"disk": "Disk", "inodes": "Inodes", "memory": "Memory", "swap": "Swap"}[r.Metric]
		if what == "" {
			what = def.label
		}
		subject = pick(fmt.Sprintf("%s on %s will run out within %g hours", what, h.Hostname, r.Threshold),
			fmt.Sprintf("%s on %s is no longer about to run out", what, h.Hostname))
	case "logs":
		window := time.Duration(r.WindowSeconds) * time.Second
		condition = fmt.Sprintf("%d matching log lines in %s (threshold %g)", int(o.Value), window, r.Threshold)
		subject = pick(fmt.Sprintf("%s on %s", r.Name, h.Hostname),
			fmt.Sprintf("%s on %s is quiet again", r.Name, h.Hostname))
	case "custom":
		condition = fmt.Sprintf("%s is %g (threshold %s %g)", r.Target, o.Value, r.Operator, r.Threshold)
		subject = pick(fmt.Sprintf("%s on %s", r.Name, h.Hostname), fmt.Sprintf("%s on %s", r.Name, h.Hostname))
	default:
		def := alertMetrics[r.Metric]
		agg := ""
		if r.Aggregation == "avg" {
			agg = fmt.Sprintf(" (average over %s)", time.Duration(r.WindowSeconds)*time.Second)
		}
		condition = fmt.Sprintf("%s is %.1f%s%s (threshold %s %g%s)", def.label, o.Value, def.unit, agg, r.Operator, r.Threshold, def.unit)
		subject = fmt.Sprintf("%s on %s", r.Name, h.Hostname)
	}
	return subject, condition
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

// pluginDetail names the plugins a plugin_down alert is about. Opening, it
// asks VictoriaMetrics which plugins report down right now (fresher than the
// inventory) and takes each one's error from the inventory; resolving, it
// reuses the names the incident opened with.
func (e *evaluator) pluginDetail(ctx context.Context, r rule, h host, act action) (names, detail string) {
	if act == actionResolve {
		return e.store.openPluginNames(ctx, r.ID, h.ID), ""
	}
	if act != actionOpen {
		return "", ""
	}
	q := fmt.Sprintf("last_over_time(pulsegrid_plugin_up%s[3m]) == 0",
		matchers(fmt.Sprintf("host_id=%q", h.ID), map[bool]string{true: "", false: "plugin=" + strconv.Quote(r.Target)}[r.Target == ""]))
	down, _ := e.queryLabel(ctx, r.TenantID, q, "plugin")
	invNames, invDetail := e.store.failingPlugins(ctx, h.ID, r.Target)
	if len(down) == 0 {
		return invNames, invDetail
	}
	errs := map[string]string{}
	for _, line := range strings.Split(invDetail, "\n") {
		if n, msg, ok := strings.Cut(line, ": "); ok {
			errs[n] = msg
		}
	}
	var lines []string
	for _, n := range down {
		msg := errs[n]
		if msg == "" {
			msg = "not collecting (no error reported yet)"
		}
		lines = append(lines, n+": "+msg)
	}
	return strings.Join(down, ", "), strings.Join(lines, "\n")
}

// queryLabel runs an instant query and returns one label's sorted values.
func (e *evaluator) queryLabel(ctx context.Context, tenantID, query, label string) ([]string, error) {
	params := url.Values{"query": {query}, "extra_label": {"tenant_id=" + tenantID}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.vmURL+"/api/v1/query?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := e.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var body struct {
		Data struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, res := range body.Data.Result {
		if v := res.Metric[label]; v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out, nil
}
