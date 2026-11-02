//go:build linux

package checks

import (
	"context"
	"net/netip"
	"os"
	"testing"
)

// Needs the internet: SENTINEL_NET_TESTS=1 go test ./agent/checks -run Trace
func TestTracePathToTheInternet(t *testing.T) {
	if os.Getenv("SENTINEL_NET_TESTS") == "" {
		t.Skip("set SENTINEL_NET_TESTS=1")
	}
	hops, note := tracePath(context.Background(), netip.MustParseAddr("1.1.1.1"), 20)
	if note != "" || len(hops) == 0 {
		t.Fatalf("note=%q hops=%v", note, hops)
	}
	answered := 0
	for _, h := range hops {
		if h.Address != "" {
			answered++
		}
		t.Logf("%2d %-16s %6.1f ms reached=%v", h.TTL, h.Address, h.RttMs, h.Reached)
	}
	if answered == 0 {
		t.Fatal("no router answered")
	}
}

func TestTracePathToLocalhostReachesIt(t *testing.T) {
	hops, note := tracePath(context.Background(), netip.MustParseAddr("127.0.0.1"), 5)
	if note != "" || len(hops) != 1 || !hops[0].Reached {
		t.Fatalf("note=%q hops=%+v", note, hops)
	}
}
