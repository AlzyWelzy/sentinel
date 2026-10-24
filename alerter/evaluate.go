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

// alertMetrics maps a rule's metric to a selector. last_over_time bridges the
// gap between pushes; max by (host_id) folds per-disk series into "the worst
// disk on this host".
var alertMetrics = map[string]struct {
	name    string
	matcher string // extra fixed label matcher, if any
	label   string // human name for messages
	unit    string
}{
	"cpu":    {"pulsegrid_cpu_usage_percent", "", "CPU usage", "%"},
	"memory": {"pulsegrid_memory_used_percent", "", "Memory usage", "%"},
	"swap":   {"pulsegrid_swap_used_percent", "", "Swap usage", "%"},
	"disk":   {"pulsegrid_disk_used_percent", "", "Disk usage", "%"},
	"load1":  {"pulsegrid_load", `period="1m"`, "Load (1m)", ""},
	"load5":  {"pulsegrid_load", `period="5m"`, "Load (5m)", ""},
}

const lastSeenKey = "pg:last_seen:" // shared with ingest/cache.go and api heartbeats.py

type evaluator struct {
	store   *store
	vmURL   string
	http    *http.Client
	rdb     *redis.Client
	log     *slog.Logger
	baseURL string // PUBLIC_DASHBOARD_URL, for links in messages
}

func (e *evaluator) evaluateAll(ctx context.Context, partition, partitions int) {
	rules, err := e.store.rules(ctx, partition, partitions)
	if err != nil {
		e.log.Error("loading rules", "err", err)
		return
	}
	for _, r := range rules {
		if ctx.Err() != nil {
			return
		}
		if err := e.evaluate(ctx, r); err != nil {
			e.log.Error("evaluating rule", "rule_id", r.ID, "tenant_id", r.TenantID, "err", err)
		}
	}
}

func (e *evaluator) evaluate(ctx context.Context, r rule) error {
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
	case "metric":
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

	now := time.Now()
	for _, h := range hosts {
		prev := states[h.ID]
		o := obs[h.ID]
		next, act := transition(prev.alertState, o, duration, now)
		if next == prev.alertState && act == actionNone {
			continue
		}
		msg := func(kind, incidentID string) message { return e.message(r, h, o, kind, incidentID) }
		if err := e.store.apply(ctx, r, h, prev, next, act, o.Value, msg); err != nil {
			return err
		}
		if act != actionNone {
			e.log.Info("alert transition", "rule_id", r.ID, "host", h.Hostname,
				"state", next.State, "value", o.Value, "tenant_id", r.TenantID)
		}
	}
	return nil
}

func (e *evaluator) metricObservations(ctx context.Context, r rule) (map[string]observation, error) {
	def, ok := alertMetrics[r.Metric]
	if !ok {
		return nil, fmt.Errorf("unknown metric %q", r.Metric)
	}
	matchers := []string{}
	if def.matcher != "" {
		matchers = append(matchers, def.matcher)
	}
	if r.HostID != nil {
		matchers = append(matchers, fmt.Sprintf("host_id=%q", *r.HostID))
	}
	query := fmt.Sprintf("max by (host_id) (last_over_time(%s{%s}[3m]))", def.name, strings.Join(matchers, ","))

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
		out[res.Metric["host_id"]] = observation{HasData: true, Breached: breached(r.Operator, v, r.Threshold), Value: v}
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
	if r.Kind == "host_down" {
		condition = fmt.Sprintf("no data for %s", time.Duration(o.Value*float64(time.Second)).Round(time.Second))
		subject = fmt.Sprintf("%s is not reporting", h.Hostname)
		if kind == "alert_resolved" {
			subject = fmt.Sprintf("%s is reporting again", h.Hostname)
		}
	} else {
		def := alertMetrics[r.Metric]
		condition = fmt.Sprintf("%s is %.1f%s (threshold %s %g%s)", def.label, o.Value, def.unit, r.Operator, r.Threshold, def.unit)
		subject = fmt.Sprintf("%s on %s", r.Name, h.Hostname)
	}
	state := "FIRING"
	if kind == "alert_resolved" {
		state = "RESOLVED"
	}
	text := fmt.Sprintf("%s: %s\n\nHost: %s\nRule: %s\n%s\nTime: %s\n",
		state, subject, h.Hostname, r.Name, condition, time.Now().UTC().Format(time.RFC1123))
	if e.baseURL != "" && incidentID != "" {
		text += fmt.Sprintf("\nDetails: %s/incidents/%s\n", strings.TrimRight(e.baseURL, "/"), incidentID)
	}
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
		},
	}
}
