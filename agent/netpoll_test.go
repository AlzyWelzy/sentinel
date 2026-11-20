package main

import (
	"math"
	"testing"

	"github.com/AlzyWelzy/sentinel/netmon/collect"
	"github.com/AlzyWelzy/sentinel/proto"
)

func TestNetSamplesAreNamedAndLabelledForTheDevice(t *testing.T) {
	in := []collect.Sample{
		{Name: "if_in_octets", Labels: map[string]string{"ifname": "Ethernet1"}, Value: 10, Counter: true},
		{Name: "cpu_usage_percent", Value: 12},
		{Name: "already_total", Value: 1, Counter: true},
		{Name: "bad", Value: math.NaN()},
	}
	out := netSamples("dev-1", in)
	if len(out) != 3 {
		t.Fatalf("NaN kept: %v", out)
	}
	if out[0].Name != "sentinel_net_if_in_octets_total" || out[0].Labels["ifname"] != "Ethernet1" || out[0].Labels["device_id"] != "dev-1" {
		t.Fatalf("%+v", out[0])
	}
	if out[1].Name != "sentinel_net_cpu_usage_percent" || out[2].Name != "sentinel_net_already_total" {
		t.Fatalf("%+v %+v", out[1], out[2])
	}
	if in[0].Labels["device_id"] != "" {
		t.Fatal("the collector's labels were modified in place")
	}
}

func TestBigPollsAreSplit(t *testing.T) {
	var got []proto.Batch
	n, err := newNetPoller(func(b proto.Batch) { got = append(got, b) }, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := proto.Batch{TimestampMs: 1, Samples: make([]proto.Sample, 2*netMaxSamplesPerBatch+5), Network: []proto.NetworkPoll{{DeviceID: "d"}}}
	n.sink(b)
	if len(got) != 3 || len(got[2].Samples) != 5 || len(got[2].Network) != 1 || len(got[0].Network) != 0 {
		t.Fatalf("%d batches", len(got))
	}
	for _, g := range got {
		if g.TimestampMs != 1 || len(g.Samples) > netMaxSamplesPerBatch {
			t.Fatal("split batch wrong")
		}
	}
}
