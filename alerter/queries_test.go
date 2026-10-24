package main

import (
	"strings"
	"testing"
)

func TestRuleQuery(t *testing.T) {
	host := "8d3c1d2e-0000-0000-0000-000000000001"
	cases := []struct {
		r    rule
		want string
	}{
		{rule{Kind: "metric", Metric: "cpu"}, `max by (host_id) (last_over_time(pulsegrid_cpu_usage_percent{}[3m]))`},
		{rule{Kind: "metric", Metric: "steal", HostID: &host},
			`max by (host_id) (last_over_time(pulsegrid_cpu_mode_percent{mode="steal",host_id="` + host + `"}[3m]))`},
		{rule{Kind: "metric", Metric: "disk_busy"}, `(max by (host_id) (rate(pulsegrid_disk_io_time_seconds_total{}[3m]))) * 100`},
		{rule{Kind: "metric", Metric: "cpu", Aggregation: "avg", WindowSeconds: 600},
			`max by (host_id) (avg_over_time(pulsegrid_cpu_usage_percent{}[600s]))`},
		{rule{Kind: "metric", Metric: "network_in", Aggregation: "avg", WindowSeconds: 300},
			`(sum by (host_id) (rate(pulsegrid_network_bytes_total{direction="rx"}[300s]))) * 8e-06`},
		{rule{Kind: "process_down", Target: `my "app"`},
			`min by (host_id) (last_over_time(pulsegrid_watched_process_count{process="my \"app\""}[3m]))`},
		{rule{Kind: "service_down", Target: "nginx"}, `min by (host_id) (last_over_time(pulsegrid_service_up{service="nginx"}[3m]))`},
		{rule{Kind: "plugin_down"}, `min by (host_id) (last_over_time(pulsegrid_plugin_up{}[3m]))`},
		{rule{Kind: "container_down", Target: "web"}, `min by (host_id) (last_over_time(pulsegrid_container_running{container="web"}[3m]))`},
		{rule{Kind: "check", Target: "c1"}, `min by (host_id) (last_over_time(pulsegrid_check_up{check_id="c1"}[3m]))`},
		{rule{Kind: "custom", Target: "jobs_waiting", Labels: map[string]string{"queue": "mail", "tenant_id": "x"}},
			`max by (host_id) (last_over_time(pulsegrid_custom_jobs_waiting{queue="mail"}[3m]))`},
		{rule{Kind: "forecast", Metric: "disk", Threshold: 72},
			`max by (host_id) (predict_linear(pulsegrid_disk_used_percent{}[24h], 259200))`},
	}
	for _, c := range cases {
		got, err := ruleQuery(c.r)
		if err != nil || got != c.want {
			t.Errorf("%+v:\n got  %s\n want %s (%v)", c.r, got, c.want, err)
		}
	}
	for _, bad := range []rule{
		{Kind: "metric", Metric: "nope"},
		{Kind: "custom", Target: `x{a="b"}`},
		{Kind: "forecast", Metric: "disk_busy", Threshold: 1},
	} {
		if _, err := ruleQuery(bad); err == nil {
			t.Errorf("%+v must fail", bad)
		}
	}
	q, _ := ruleQuery(rule{Kind: "anomaly", Metric: "cpu", Threshold: 3})
	if !strings.Contains(q, "stddev_over_time") || !strings.Contains(q, "count_over_time") {
		t.Errorf("anomaly query: %s", q)
	}
}

func TestChannelSeverity(t *testing.T) {
	c := channel{MinSeverity: "warning"}
	if c.wants("info") || !c.wants("warning") || !c.wants("critical") {
		t.Fatal("severity filter")
	}
}

func TestDescribe(t *testing.T) {
	h := host{ID: "c", Hostname: "Website", IsCheck: true}
	r := rule{Kind: "check", Name: "site", Check: &checkInfo{Name: "Website"}}
	s, c := describe(r, h, observation{Value: 2, Total: 3}, false)
	if s != "Website is down" || c != "Failing from 2 of 3 locations" {
		t.Fatalf("%q %q", s, c)
	}
	s, _ = describe(rule{Kind: "forecast", Metric: "disk", Threshold: 48}, host{Hostname: "db1"}, observation{Value: 104}, false)
	if s != "Disk on db1 will run out within 48 hours" {
		t.Fatal(s)
	}
}
