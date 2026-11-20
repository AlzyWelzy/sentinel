package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

func fakePVE(t *testing.T, token string) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != token {
			http.Error(w, "authentication failure", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api2/json/cluster/resources":
			w.Write([]byte(`{"data":[
				{"type":"node","node":"pve1","status":"online","cpu":0.25,"maxcpu":32,"mem":1e10,"maxmem":6.4e10,"disk":1e9,"maxdisk":1e11,"uptime":1000},
				{"type":"node","node":"pve2","status":"offline"},
				{"type":"qemu","node":"pve1","vmid":100,"name":"web","status":"running","cpu":0.5,"maxcpu":4,"mem":2e9,"maxmem":4e9,"netin":10,"netout":20,"diskread":1,"diskwrite":2},
				{"type":"qemu","node":"pve1","vmid":101,"name":"old","status":"stopped","mem":9e9},
				{"type":"qemu","node":"pve1","vmid":9000,"name":"tpl","template":1,"status":"stopped"},
				{"type":"storage","node":"pve1","storage":"ceph","status":"available","disk":5e11,"maxdisk":1e12,"shared":1},
				{"type":"pool","id":"pool/x"}]}`))
		case "/api2/json/cluster/status":
			w.Write([]byte(`{"data":[{"type":"cluster","name":"prod","quorate":1,"nodes":2},{"type":"node","name":"pve1","online":1}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestPollProxmox(t *testing.T) {
	srv := fakePVE(t, "PVEAPIToken=mon@pve!sentinel=s3cret")
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")
	d := proto.NetworkDevice{ID: "pve", Address: addr, Credential: proto.SNMPCredential{
		Version: "proxmox", TokenUser: "mon@pve", TokenName: "sentinel", TokenValue: "s3cret", InsecureTLS: true}}

	b := pollProxmox(context.Background(), d, newPVEClient(true))
	p := b.Network[0]
	if !p.OK || p.System.Name != "prod" || p.System.Vendor != "Proxmox" || !strings.Contains(p.System.Descr, "2 nodes") {
		t.Fatalf("%+v %+v", p, p.System)
	}
	got := map[string]float64{}
	for _, s := range b.Samples {
		key := s.Name + "|" + s.Labels["type"] + "|" + s.Labels["node"] + s.Labels["name"] + s.Labels["storage"]
		got[key] = s.Value
		if s.Labels["device_id"] != "pve" {
			t.Fatalf("sample without the device: %+v", s)
		}
	}
	want := map[string]float64{
		"sentinel_net_pve_up|node|pve1":                     1,
		"sentinel_net_pve_up|node|pve2":                     0,
		"sentinel_net_pve_up|qemu|pve1web":                  1,
		"sentinel_net_pve_up|qemu|pve1old":                  0,
		"sentinel_net_pve_cpu_ratio|qemu|pve1web":           0.5,
		"sentinel_net_pve_disk_used_bytes|storage|pve1ceph": 5e11,
		"sentinel_net_pve_cluster_quorate||":                1,
		"sentinel_net_snmp_up||":                            1,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	for k := range got {
		if strings.Contains(k, "tpl") || strings.Contains(k, "memory_used_bytes|qemu|pve1old") || strings.Contains(k, "|node|pve2") && !strings.HasPrefix(k, "sentinel_net_pve_up") {
			t.Errorf("unexpected %s", k)
		}
	}

	// A self-signed certificate without the opt-in, and a wrong token, say why.
	b = pollProxmox(context.Background(), d, newPVEClient(false))
	if b.Network[0].OK || !strings.Contains(b.Network[0].Error, "self-signed") {
		t.Fatalf("certificate: %+v", b.Network[0])
	}
	d.Credential.TokenValue = "wrong"
	b = pollProxmox(context.Background(), d, newPVEClient(true))
	if b.Network[0].OK || !strings.Contains(b.Network[0].Error, "refused the API token") {
		t.Fatalf("token: %+v", b.Network[0])
	}
}

func TestPVEBaseURL(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.5":           "https://10.0.0.5:8006/api2/json",
		"pve.example:443":    "https://pve.example:443/api2/json",
		"[2001:db8::5]:8006": "https://[2001:db8::5]:8006/api2/json",
		"2001:db8::5":        "https://[2001:db8::5]:8006/api2/json",
	} {
		if got := pveBaseURL(in); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
}
