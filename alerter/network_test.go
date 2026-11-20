package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// The API validates rules against the same keys (app/services/netconditions.py).
var sharedConditionKeys = []string{
	"bgp_peer_flapped", "bgp_peer_not_established", "device_rebooted", "fortigate_cpu_high", "fortigate_memory_high",
	"ha_out_of_sync", "hardware_sensor_alarm", "interface_down", "interface_errors", "interface_utilisation",
	"lag_member_down", "optic_receive_power_low", "ospf_neighbour_not_full", "sd_wan_latency_high", "sd_wan_link_dead",
	"sd_wan_packet_loss", "sensor_above_critical_threshold", "sensor_above_warning_threshold", "sophos_disk_almost_full",
	"sophos_memory_high", "vpn_tunnel_down",
}

func TestNetworkCatalogMatchesTheAPI(t *testing.T) {
	var got []string
	for k, c := range networkConditions() {
		got = append(got, k)
		if strings.Contains(c.Expr, "beacon_") || strings.Contains(c.Expr, "device_id") || strings.Contains(c.Expr, "profile=") {
			t.Errorf("%s not translated: %s", k, c.Expr)
		}
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(sharedConditionKeys, ",") {
		t.Fatalf("catalog differs from the API's:\n got %v\nwant %v", got, sharedConditionKeys)
	}
}

func TestTranslateExpr(t *testing.T) {
	cases := map[string]string{
		`beacon_disk_usage_percent{profile="sophos-sfos"} > 90`:                                `sentinel_net_disk_usage_percent > 90`,
		`beacon_x{profile="a", name="b"} > on(device_id, index) group_left beacon_y`:           `sentinel_net_x{ name="b"} > on(host_id, index) group_left sentinel_net_y`,
		`beacon_bgp_peer_state != 6 and on(device_id, peer) beacon_bgp_peer_admin_status == 2`: `sentinel_net_bgp_peer_state != 6 and on(host_id, peer) sentinel_net_bgp_peer_admin_status == 2`,
	}
	for in, want := range cases {
		if got := translateExpr(in); got != want {
			t.Errorf("%s\n got %s\nwant %s", in, got, want)
		}
	}
}

func TestNetworkObservationsNoSeriesIsHealthy(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
			{"metric":{"host_id":"sw1","ifname":"Ethernet3"},"value":[1,"97.5"]},
			{"metric":{"host_id":"sw1","ifname":"Ethernet1"},"value":[1,"91"]}]}}`))
	}))
	defer srv.Close()
	e := &evaluator{vmURL: srv.URL, http: srv.Client()}
	r := rule{TenantID: "t", Kind: "network", Target: "interface_utilisation", Threshold: 90}
	hosts := []host{{ID: "sw1", Network: true}, {ID: "sw2", Network: true}, {ID: "web", Network: false}}
	obs, err := e.networkObservations(context.Background(), r, hosts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotQuery, "> 90)") {
		t.Fatalf("threshold not in the query: %s", gotQuery)
	}
	if o := obs["sw1"]; !o.Breached || o.Value != 97.5 {
		t.Fatalf("sw1: %+v", o)
	}
	if o := obs["sw2"]; !o.HasData || o.Breached {
		t.Fatalf("a device with no matching series is healthy: %+v", o)
	}
	if _, ok := obs["web"]; ok {
		t.Fatal("servers aren't judged by network rules")
	}
	if d := e.networkDetail(context.Background(), r, host{ID: "sw1"}); d != "ifname=Ethernet1; ifname=Ethernet3" {
		t.Fatalf("detail %q", d)
	}
	if _, err := e.networkObservations(context.Background(), rule{Kind: "network", Target: "nope"}, hosts); err == nil {
		t.Fatal("unknown condition accepted")
	}
}
