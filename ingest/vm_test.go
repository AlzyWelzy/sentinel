package main

import (
	"strings"
	"testing"
	"time"

	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

func req(samples ...proto.Sample) proto.MetricsRequest {
	return proto.MetricsRequest{Batches: []proto.Batch{{TimestampMs: 1700000000000, Samples: samples}}}
}

var host1 = hostIdentity{HostID: "host-1", TenantID: "t1", Active: true}

// convert runs toPrometheusText for host-1 with no checks and returns tenant t1's body.
func convert(r proto.MetricsRequest) ([]byte, int, int) {
	bodies, kept, dropped := toPrometheusText(r, host1, &hostConfig{checks: map[string]checkDef{}}, time.UnixMilli(r.Batches[0].TimestampMs))
	return bodies["t1"], kept, dropped
}

func TestHostIDComesFromIngest(t *testing.T) {
	body, kept, dropped := convert(req(proto.Sample{Name: "sentinel_cpu_usage_percent", Value: 12.5}))
	if kept != 1 || dropped != 0 {
		t.Fatalf("kept=%d dropped=%d", kept, dropped)
	}
	want := `sentinel_cpu_usage_percent{host_id="host-1"} 12.5 1700000000000` + "\n"
	if string(body) != want {
		t.Fatalf("got %q, want %q", body, want)
	}
}

// An agent must never be able to write into another tenant or host by setting
// the labels that decide ownership.
func TestReservedLabelsRejected(t *testing.T) {
	for _, label := range []string{"tenant_id", "host_id"} {
		s := proto.Sample{Name: "sentinel_cpu_usage_percent", Value: 1, Labels: map[string]string{label: "someone-else"}}
		body, kept, dropped := convert(req(s))
		if kept != 0 || dropped != 1 || len(body) != 0 {
			t.Fatalf("%s: sample with reserved label was accepted: %q", label, body)
		}
	}
}

func TestInvalidNamesDropped(t *testing.T) {
	cases := []proto.Sample{
		{Name: "node_cpu_seconds_total"},   // not in our namespace
		{Name: "sentinel_cpu{evil=\"x\"}"}, // injection via name
		{Name: "sentinel_ok", Labels: map[string]string{"Bad-Label": "x"}},
	}
	_, kept, dropped := convert(req(cases...))
	if kept != 0 || dropped != len(cases) {
		t.Fatalf("kept=%d dropped=%d", kept, dropped)
	}
}

func TestLabelValuesEscaped(t *testing.T) {
	s := proto.Sample{Name: "sentinel_disk_used_percent", Value: 1, Labels: map[string]string{
		"mountpoint": "/a\"},tenant_id=\"x",
	}}
	body, kept, _ := convert(req(s))
	if kept != 1 {
		t.Fatal("sample dropped")
	}
	if !strings.Contains(string(body), `mountpoint="/a\"},tenant_id=\"x"`) {
		t.Fatalf("value not escaped: %q", body)
	}
}

func TestCheckSamplesRouted(t *testing.T) {
	hc := &hostConfig{region: "region1", checks: map[string]checkDef{
		"own":    {Check: proto.Check{ID: "own"}, TenantID: "t1"},
		"public": {Check: proto.Check{ID: "public"}, TenantID: "t2", OnProbes: true},
	}}
	r := req(
		proto.Sample{Name: "sentinel_check_up", Value: 1, Labels: map[string]string{"check_id": "own"}},
		proto.Sample{Name: "sentinel_check_up", Value: 0, Labels: map[string]string{"check_id": "public", "probe": "spoofed"}},
		proto.Sample{Name: "sentinel_check_up", Value: 1, Labels: map[string]string{"check_id": "someone-elses"}},
	)
	bodies, kept, dropped := toPrometheusText(r, host1, hc, time.UnixMilli(r.Batches[0].TimestampMs))
	if kept != 2 || dropped != 1 {
		t.Fatalf("kept=%d dropped=%d", kept, dropped)
	}
	if got := string(bodies["t1"]); got != `sentinel_check_up{host_id="host-1",check_id="own"} 1 1700000000000`+"\n" {
		t.Fatalf("t1: %q", got)
	}
	if got := string(bodies["t2"]); got != `sentinel_check_up{probe="region1",check_id="public"} 0 1700000000000`+"\n" {
		t.Fatalf("t2: %q", got)
	}
}

func TestConfigVersionChanges(t *testing.T) {
	a := proto.AgentConfig{IntervalSeconds: 30}
	b := a
	b.Checks = []proto.Check{{ID: "x", Type: "tcp", Target: "a:1"}}
	if configVersion(a) == configVersion(b) || configVersion(a) != configVersion(a) {
		t.Fatal("version must follow content")
	}
	a.Version = "ignored"
	if configVersion(a) != configVersion(proto.AgentConfig{IntervalSeconds: 30}) {
		t.Fatal("version field must not affect the version")
	}
}

func TestDiffPackages(t *testing.T) {
	prev := []proto.Package{{Name: "a", Version: "1"}, {Name: "b", Version: "1"}}
	cur := []proto.Package{{Name: "a", Version: "2"}, {Name: "c", Version: "1"}}
	got := diffPackages(prev, cur, time.Unix(0, 0))
	if len(got) != 3 || got[0].Change != "upgraded" || got[1].Change != "removed" || got[2].Change != "installed" {
		t.Fatalf("%+v", got)
	}
}
