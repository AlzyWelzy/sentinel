package checks

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

func runOne(t *testing.T, r *Runner, c proto.Check) proto.CheckResult {
	t.Helper()
	r.Set([]proto.Check{c})
	r.mu.Lock()
	s := r.checks[c.ID]
	r.mu.Unlock()
	res, _ := r.run(context.Background(), s)
	return res
}

func TestTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	r := NewRunner("test")
	if res := runOne(t, r, proto.Check{ID: "a", Type: "tcp", Target: ln.Addr().String()}); !res.OK {
		t.Fatalf("open port reported down: %s", res.Detail)
	}
	addr := ln.Addr().String()
	ln.Close()
	if res := runOne(t, r, proto.Check{ID: "b", Type: "tcp", Target: addr}); res.OK {
		t.Fatal("closed port reported up")
	}
}

func TestHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/down" {
			w.WriteHeader(503)
			return
		}
		w.Write([]byte("hello world"))
	}))
	defer srv.Close()
	r := NewRunner("test")
	cases := []struct {
		c  proto.Check
		ok bool
	}{
		{proto.Check{ID: "1", Type: "http", Target: srv.URL}, true},
		{proto.Check{ID: "2", Type: "http", Target: srv.URL + "/down"}, false},
		{proto.Check{ID: "3", Type: "http", Target: srv.URL + "/down", Params: map[string]string{"expect_status": "503"}}, true},
		{proto.Check{ID: "4", Type: "http", Target: srv.URL, Params: map[string]string{"keyword": "world"}}, true},
		{proto.Check{ID: "5", Type: "http", Target: srv.URL, Params: map[string]string{"keyword": "nope"}}, false},
		{proto.Check{ID: "6", Type: "http", Target: srv.URL, Params: map[string]string{"keyword": "world", "keyword_absent": "true"}}, false},
	}
	for _, tc := range cases {
		if res := runOne(t, r, tc.c); res.OK != tc.ok {
			t.Errorf("check %s: ok=%v want %v (%s)", tc.c.ID, res.OK, tc.ok, res.Detail)
		}
	}
}

func TestTLSExpiry(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	r := NewRunner("test")
	r.Set([]proto.Check{{ID: "t", Type: "http", Target: srv.URL, Params: map[string]string{"tls_skip_verify": "true"}}})
	r.RunDue(context.Background())
	res, samples := r.Results()
	if len(res) != 1 || !res[0].OK {
		t.Fatalf("result %+v", res)
	}
	found := false
	for _, s := range samples {
		if s.Name == "sentinel_check_tls_expiry_seconds" && s.Value > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("no tls expiry sample")
	}
}

func TestFileChanged(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	os.WriteFile(p, []byte("a"), 0o600)
	r := NewRunner("test")
	c := proto.Check{ID: "f", Type: "file", Target: p, Params: map[string]string{"mode": "changed"}}
	if res := runOne(t, r, c); !res.OK {
		t.Fatal("first run should be ok")
	}
	s := r.checks["f"]
	os.WriteFile(p, []byte("b"), 0o600)
	if res, _ := r.run(context.Background(), s); res.OK {
		t.Fatal("change not detected")
	}
	if res, _ := r.run(context.Background(), s); !res.OK {
		t.Fatal("should recover after reporting the change")
	}
}

func TestLogPattern(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.log")
	os.WriteFile(p, []byte("ERROR old\n"), 0o600)
	r := NewRunner("test")
	c := proto.Check{ID: "l", Type: "log", Target: p, Params: map[string]string{"pattern": "ERROR"}}
	if res := runOne(t, r, c); !res.OK {
		t.Fatal("old lines must not alert")
	}
	s := r.checks["l"]
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("info fine\nERROR disk failed\npartial ERROR")
	f.Close()
	res, _ := r.run(context.Background(), s)
	if res.OK || res.Detail != "1 matching lines; last: ERROR disk failed" {
		t.Fatalf("got %+v", res)
	}
	f, _ = os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(" now\n")
	f.Close()
	if res, _ := r.run(context.Background(), s); res.OK {
		t.Fatal("completed partial line should match")
	}
	// Truncation (rotation) restarts from the top.
	os.WriteFile(p, []byte("ok\n"), 0o600)
	if res, _ := r.run(context.Background(), s); !res.OK {
		t.Fatalf("after truncate: %+v", res)
	}
}

func TestSetKeepsState(t *testing.T) {
	r := NewRunner("test")
	c := proto.Check{ID: "x", Type: "tcp", Target: "127.0.0.1:1"}
	r.Set([]proto.Check{c})
	first := r.checks["x"]
	r.Set([]proto.Check{c})
	if r.checks["x"] != first {
		t.Fatal("identical definition should keep its schedule")
	}
	r.Set(nil)
	if len(r.checks) != 0 {
		t.Fatal("removed check still scheduled")
	}
}

func TestPublicOnlyGuard(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	r := NewRunner("test")
	res := runOne(t, r, proto.Check{ID: "p", Type: "tcp", Target: ln.Addr().String(), Params: map[string]string{"public_only": "true"}})
	if res.OK {
		t.Fatal("probe check reached loopback")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	res = runOne(t, r, proto.Check{ID: "h", Type: "http", Target: srv.URL, Params: map[string]string{"public_only": "true"}})
	if res.OK {
		t.Fatal("probe http check reached loopback")
	}
	for addr, want := range map[string]bool{"8.8.8.8": true, "10.1.2.3": false, "169.254.169.254": false,
		"100.64.1.1": false, "::1": false, "2606:4700::1111": true, "::ffff:192.168.1.1": false, "fd00::1": false} {
		if got := publicAddress(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: %v", addr, got)
		}
	}
}

func TestFailuresAreHeldUntilDelivered(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.log")
	os.WriteFile(p, []byte(""), 0o600)
	r := NewRunner("test")
	r.Set([]proto.Check{{ID: "l", Type: "log", Target: p, Params: map[string]string{"pattern": "ERROR"}, IntervalSeconds: 10}})
	due := func() {
		r.mu.Lock()
		for _, s := range r.checks {
			s.next = time.Time{}
		}
		r.mu.Unlock()
		r.RunDue(context.Background())
	}
	due() // primes the log position
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("ERROR boom\n")
	f.Close()
	due() // sees the error
	due() // nothing new: passes, but the failure must still be reported
	res, samples := r.Results()
	if len(res) != 1 || res[0].OK {
		t.Fatalf("failure lost before delivery: %+v", res)
	}
	var up float64 = -1
	for _, s := range samples {
		if s.Name == "sentinel_check_up" {
			up = s.Value
		}
	}
	if up != 0 {
		t.Fatalf("held sample should be the failing one, got %v", up)
	}
	r.Ack(res)
	if res, _ := r.Results(); !res[0].OK {
		t.Fatal("after delivery the latest (passing) result is reported")
	}
}
