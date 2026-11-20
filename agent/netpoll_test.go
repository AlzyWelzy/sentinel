package main

import (
	"math"
	"testing"

	"github.com/AlzyWelzy/pulsegrid-beyond/netmon/collect"
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
