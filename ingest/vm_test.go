package main

import (
	"strings"
	"testing"

	"github.com/example-org/pulsegrid/proto"
)

func req(samples ...proto.Sample) proto.MetricsRequest {
	return proto.MetricsRequest{Batches: []proto.Batch{{TimestampMs: 1700000000000, Samples: samples}}}
}

func TestHostIDComesFromIngest(t *testing.T) {
	body, kept, dropped := toPrometheusText(req(proto.Sample{Name: "pulsegrid_cpu_usage_percent", Value: 12.5}), "host-1")
	if kept != 1 || dropped != 0 {
		t.Fatalf("kept=%d dropped=%d", kept, dropped)
	}
	want := `pulsegrid_cpu_usage_percent{host_id="host-1"} 12.5 1700000000000` + "\n"
	if string(body) != want {
		t.Fatalf("got %q, want %q", body, want)
	}
}

// An agent must never be able to write into another tenant or host by setting
// the labels that decide ownership.
func TestReservedLabelsRejected(t *testing.T) {
	for _, label := range []string{"tenant_id", "host_id"} {
		s := proto.Sample{Name: "pulsegrid_cpu_usage_percent", Value: 1, Labels: map[string]string{label: "someone-else"}}
		body, kept, dropped := toPrometheusText(req(s), "host-1")
		if kept != 0 || dropped != 1 || len(body) != 0 {
			t.Fatalf("%s: sample with reserved label was accepted: %q", label, body)
		}
	}
}

func TestInvalidNamesDropped(t *testing.T) {
	cases := []proto.Sample{
		{Name: "node_cpu_seconds_total"},    // not in our namespace
		{Name: "pulsegrid_cpu{evil=\"x\"}"}, // injection via name
		{Name: "pulsegrid_ok", Labels: map[string]string{"Bad-Label": "x"}},
	}
	_, kept, dropped := toPrometheusText(req(cases...), "host-1")
	if kept != 0 || dropped != len(cases) {
		t.Fatalf("kept=%d dropped=%d", kept, dropped)
	}
}

func TestLabelValuesEscaped(t *testing.T) {
	s := proto.Sample{Name: "pulsegrid_disk_used_percent", Value: 1, Labels: map[string]string{
		"mountpoint": "/a\"},tenant_id=\"x",
	}}
	body, kept, _ := toPrometheusText(req(s), "host-1")
	if kept != 1 {
		t.Fatal("sample dropped")
	}
	if !strings.Contains(string(body), `mountpoint="/a\"},tenant_id=\"x"`) {
		t.Fatalf("value not escaped: %q", body)
	}
}
