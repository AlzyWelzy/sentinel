package checks

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/AlzyWelzy/sentinel/proto"
)

func TestTargetOfEachCheckType(t *testing.T) {
	cases := []struct {
		c          proto.Check
		host, port string
	}{
		{proto.Check{Type: "tcp", Target: "db.example.com:5432"}, "db.example.com", "5432"},
		{proto.Check{Type: "http", Target: "https://example.com/health"}, "example.com", "443"},
		{proto.Check{Type: "http", Target: "http://example.com:8080/"}, "example.com", "8080"},
		{proto.Check{Type: "tls", Target: "example.com"}, "example.com", "443"},
		{proto.Check{Type: "ping", Target: "10.0.0.1"}, "10.0.0.1", "443"},
		{proto.Check{Type: "dns", Target: "example.com"}, "example.com", ""},
	}
	for _, tc := range cases {
		h, p, ok := target(tc.c)
		if !ok || h != tc.host || p != tc.port {
			t.Fatalf("%+v: got %s %s %v", tc.c, h, p, ok)
		}
	}
	if _, _, ok := target(proto.Check{Type: "file", Target: "/etc/passwd"}); ok {
		t.Fatal("file checks have no network target")
	}
}

func TestDiagnoseARefusedPort(t *testing.T) {
	// A port nothing listens on: grab one, then close it.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	d := diagnose(context.Background(), proto.Check{Type: "tcp", Target: addr}, false)
	if d == nil || len(d.Connect) != 1 || d.Connect[0].OK {
		t.Fatalf("diagnosis %+v", d)
	}
	if !strings.Contains(d.Summary, "TCP to "+addr) {
		t.Fatalf("summary %q", d.Summary)
	}
	// Probes never look at private addresses, even while diagnosing.
	priv := diagnose(context.Background(), proto.Check{Type: "tcp", Target: addr}, true)
	if len(priv.Connect) != 0 || len(priv.Path) != 0 {
		t.Fatalf("public-only diagnosis touched a private address: %+v", priv)
	}
}

func TestSummarize(t *testing.T) {
	d := &proto.Diagnosis{
		DNS:     &proto.DNSStep{Host: "shop.example.com", Addresses: []string{"203.0.113.9"}, ElapsedMs: 12},
		Connect: []proto.ConnectStep{{Address: "203.0.113.9:443", Error: "i/o timeout"}},
		Path:    []proto.Hop{{TTL: 1, Address: "10.0.0.1"}, {TTL: 2, Address: "198.51.100.1"}, {TTL: 3}, {TTL: 4}},
	}
	got := summarize(d)
	want := "DNS ok (203.0.113.9, 12 ms) · TCP to 203.0.113.9:443 i/o timeout · path stops after 198.51.100.1 (hop 2 of 4 tried)"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	if s := summarize(&proto.Diagnosis{DNS: &proto.DNSStep{Host: "x.invalid", Error: "no such host"}}); s != "DNS failed for x.invalid: no such host" {
		t.Fatal(s)
	}
}
