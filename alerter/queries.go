package main

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// metricDef describes how a rule's metric is read. Gauges use
// last_over_time (or the rule's aggregation) to bridge the gap between
// pushes; counters use rate. max by (host_id) folds per-disk, per-mount and
// per-core series into "the worst one on this host"; sum folds interfaces.
type metricDef struct {
	name    string
	matcher string  // extra fixed label matcher, if any
	rate    bool    // a counter: read its per-second rate
	scale   float64 // multiply the result (rate of seconds → percent, bytes → Mbit)
	fold    string  // max (default) or sum
	label   string  // human name for messages
	unit    string
}

var alertMetrics = map[string]metricDef{
	"cpu":         {name: "pulsegrid_cpu_usage_percent", label: "CPU usage", unit: "%"},
	"memory":      {name: "pulsegrid_memory_used_percent", label: "Memory usage", unit: "%"},
	"swap":        {name: "pulsegrid_swap_used_percent", label: "Swap usage", unit: "%"},
	"disk":        {name: "pulsegrid_disk_used_percent", label: "Disk usage", unit: "%"},
	"load1":       {name: "pulsegrid_load", matcher: `period="1m"`, label: "Load (1m)"},
	"load5":       {name: "pulsegrid_load", matcher: `period="5m"`, label: "Load (5m)"},
	"iowait":      {name: "pulsegrid_cpu_mode_percent", matcher: `mode="iowait"`, label: "CPU iowait", unit: "%"},
	"steal":       {name: "pulsegrid_cpu_mode_percent", matcher: `mode="steal"`, label: "CPU steal", unit: "%"},
	"inodes":      {name: "pulsegrid_disk_inodes_used_percent", label: "Inode usage", unit: "%"},
	"disk_busy":   {name: "pulsegrid_disk_io_time_seconds_total", rate: true, scale: 100, label: "Disk busy time", unit: "%"},
	"network_in":  {name: "pulsegrid_network_bytes_total", matcher: `direction="rx"`, rate: true, scale: 8 / 1e6, fold: "sum", label: "Network in", unit: " Mbit/s"},
	"network_out": {name: "pulsegrid_network_bytes_total", matcher: `direction="tx"`, rate: true, scale: 8 / 1e6, fold: "sum", label: "Network out", unit: " Mbit/s"},
}

// Process, service, plugin and container rules read what the agent reports:
// a count of matching processes, or 1/0. All breach below 1.
var targetMetrics = map[string]struct{ name, label string }{
	"process_down":   {"pulsegrid_watched_process_count", "process"},
	"service_down":   {"pulsegrid_service_up", "service"},
	"plugin_down":    {"pulsegrid_plugin_up", "plugin"},
	"container_down": {"pulsegrid_container_running", "container"},
	"check":          {"pulsegrid_check_up", "check_id"},
}

var customNameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,150}$`)
var labelKeyRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,49}$`)

func matchers(extra ...string) string {
	var out []string
	for _, m := range extra {
		if m != "" {
			out = append(out, m)
		}
	}
	return "{" + strings.Join(out, ",") + "}"
}

func hostMatcher(r rule) string {
	if r.HostID != nil {
		return fmt.Sprintf("host_id=%q", *r.HostID)
	}
	return ""
}

// window renders a duration for a range selector.
func rangeWindow(seconds int) string {
	if seconds <= 0 {
		seconds = 300
	}
	return strconv.Itoa(seconds) + "s"
}

// ruleQuery builds the MetricsQL whose per-host value the rule compares.
func ruleQuery(r rule) (string, error) {
	switch r.Kind {
	case "metric":
		def, ok := alertMetrics[r.Metric]
		if !ok {
			return "", fmt.Errorf("unknown metric %q", r.Metric)
		}
		return metricExpr(def, r), nil
	case "custom":
		if !customNameRe.MatchString(r.Target) {
			return "", fmt.Errorf("invalid custom metric %q", r.Target)
		}
		ms := []string{hostMatcher(r)}
		keys := make([]string, 0, len(r.Labels))
		for k := range r.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if labelKeyRe.MatchString(k) && k != "tenant_id" {
				ms = append(ms, k+"="+strconv.Quote(r.Labels[k]))
			}
		}
		name := "pulsegrid_custom_" + strings.TrimPrefix(r.Target, "pulsegrid_custom_")
		def := metricDef{name: name}
		sel := name + matchers(ms...)
		return aggregate(def, r, sel), nil
	case "anomaly":
		def, ok := alertMetrics[r.Metric]
		if !ok {
			return "", fmt.Errorf("unknown metric %q", r.Metric)
		}
		return anomalyExpr(def, r), nil
	case "forecast":
		def, ok := alertMetrics[r.Metric]
		if !ok || def.rate {
			return "", fmt.Errorf("metric %q can't be forecast", r.Metric)
		}
		// Where the worst series will be in threshold hours, from two
		// trends: a short one catches a sudden fill (a runaway log), a long
		// one steady growth; either reaching the limit counts.
		short, long := "1h", "6h"
		if r.Threshold > 24 {
			short, long = "6h", "24h"
		}
		sel := def.name + matchers(def.matcher, hostMatcher(r))
		h := int(r.Threshold * 3600)
		return fmt.Sprintf(`max by (host_id) (label_set(predict_linear(%[1]s[%[2]s], %[4]d), "trend", "short") or label_set(predict_linear(%[1]s[%[3]s], %[4]d), "trend", "long"))`,
			sel, short, long, h), nil
	}
	if t, ok := targetMetrics[r.Kind]; ok {
		target := ""
		if r.Target != "" {
			target = t.label + "=" + strconv.Quote(r.Target)
		}
		if r.Check != nil && r.Check.eventLike() {
			// A log match or a file change is one failing sample between
			// passing ones: look at the whole last minute, not the newest.
			return fmt.Sprintf("min by (host_id) (min_over_time(%s%s[1m]))", t.name, matchers(target, hostMatcher(r))), nil
		}
		return fmt.Sprintf("min by (host_id) (last_over_time(%s%s[3m]))", t.name, matchers(target, hostMatcher(r))), nil
	}
	return "", fmt.Errorf("no query for rule kind %q", r.Kind)
}

// probeCheckQuery counts, for an uptime check run by the probes, how many
// probe locations currently see it failing, and how many report at all.
func probeCheckQuery(checkID string) (failing, total string) {
	sel := fmt.Sprintf("last_over_time(pulsegrid_check_up{check_id=%q}[3m])", checkID)
	return fmt.Sprintf("sum(%s < bool 1)", sel), fmt.Sprintf("count(%s)", sel)
}

func metricExpr(def metricDef, r rule) string {
	sel := def.name + matchers(def.matcher, hostMatcher(r))
	return aggregate(def, r, sel)
}

// aggregate applies the rule's aggregation over its window to a selector,
// then folds per-host.
func aggregate(def metricDef, r rule, sel string) string {
	fold := def.fold
	if fold == "" {
		fold = "max"
	}
	var inner string
	if def.rate {
		w := "3m"
		if r.Aggregation != "last" && r.Aggregation != "" {
			w = rangeWindow(r.WindowSeconds)
		}
		inner = fmt.Sprintf("rate(%s[%s])", sel, w)
		if r.Aggregation == "max" || r.Aggregation == "min" {
			inner = fmt.Sprintf("%s_over_time(rate(%s[3m])[%s:1m])", r.Aggregation, sel, w)
		}
	} else {
		switch r.Aggregation {
		case "avg", "max", "min":
			inner = fmt.Sprintf("%s_over_time(%s[%s])", r.Aggregation, sel, rangeWindow(r.WindowSeconds))
		default:
			inner = fmt.Sprintf("last_over_time(%s[3m])", sel)
		}
	}
	q := fmt.Sprintf("%s by (host_id) (%s)", fold, inner)
	if def.scale != 0 && def.scale != 1 {
		q = fmt.Sprintf("(%s) * %g", q, def.scale)
	}
	return q
}

// anomalyExpr scores the last 10 minutes against the same metric over the
// past week: how many standard deviations above its usual level it is. The
// standard deviation has a floor so a metric that's been flat for days
// doesn't page on a tiny wobble, and hosts with under a day of history are
// left out.
func anomalyExpr(def metricDef, r rule) string {
	sel := def.name + matchers(def.matcher, hostMatcher(r))
	series := fmt.Sprintf("max by (host_id) (%s)", sel)
	if def.rate {
		series = fmt.Sprintf("sum by (host_id) (rate(%s[5m]))", sel)
	}
	floor := 1.0
	if def.rate && def.scale != 0 {
		floor = 1 / def.scale // one unit (1% or 1 Mbit/s) in raw terms
	}
	return fmt.Sprintf(
		"((avg_over_time((%[1]s)[10m:1m]) - avg_over_time((%[1]s)[7d:5m])) / clamp_min(stddev_over_time((%[1]s)[7d:5m]), %[2]g))"+
			" and on (host_id) (count_over_time((%[1]s)[7d:1h]) > 24)",
		series, floor)
}

// eventLike checks report events (a log line, a file change) rather than a
// lasting state.
func (c *checkInfo) eventLike() bool {
	return c.Type == "log" || (c.Type == "file" && c.Mode == "changed")
}
