//go:build linux

package collector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestParsePressure(t *testing.T) {
	got := parsePressure("some avg10=1.50 avg60=0.75 avg300=0.10 total=123\nfull avg10=0.00 avg60=0.25 avg300=0.05 total=9\n", "io")
	want := map[string]float64{"some/60": 0.75, "some/300": 0.10, "full/60": 0.25, "full/300": 0.05}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for _, s := range got {
		if s.Labels["resource"] != "io" || want[s.Labels["kind"]+"/"+s.Labels["window"]] != s.Value {
			t.Fatalf("unexpected %+v", s)
		}
	}
}

func TestCountTCP(t *testing.T) {
	f := filepath.Join(t.TempDir(), "tcp")
	os.WriteFile(f, []byte("  sl  local_address rem_address   st\n"+
		"   0: 00000000:0016 00000000:0000 0A 0\n"+
		"   1: 0100007F:1F90 0100007F:D2F4 01 0\n"+
		"   2: 0100007F:1F90 0100007F:D2F6 01 0\n"+
		"   3: 0100007F:1F90 0100007F:D2F8 06 0\n"), 0o644)
	counts := map[string]int{}
	countTCP(f, counts)
	if counts["listen"] != 1 || counts["established"] != 2 || counts["time_wait"] != 1 {
		t.Fatalf("counts %v", counts)
	}
}

func TestLoggedInSessions(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) { os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644) }
	write("1", "UID=1000\nSTATE=active\nCLASS=manager\n")
	write("2", "UID=1000\nSTATE=closing\nCLASS=user\n")
	write("3", "UID=1000\nSTATE=active\nCLASS=user\n")
	write("4", "UID=0\nSTATE=online\nCLASS=user\n")
	if n, ok := loggedInSessions(dir); !ok || n != 2 {
		t.Fatalf("got %d %v, want 2 true", n, ok)
	}
	if _, ok := loggedInSessions(filepath.Join(dir, "missing")); ok {
		t.Fatal("a missing directory should report no logind")
	}
}

// A real collection on this machine reports the new families.
func TestCollectReportsSystemDetail(t *testing.T) {
	c, _ := New()
	ctx := context.Background()
	c.Collect(ctx)
	samples, err := c.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, s := range samples {
		have[s.Name] = true
	}
	for _, name := range []string{
		"sentinel_memory_bytes", "sentinel_disk_total_bytes", "sentinel_disk_used_bytes",
		"sentinel_procs", "sentinel_context_switches_total", "sentinel_interrupts_total",
		"sentinel_tcp_connections", "sentinel_threads_total", "sentinel_user_cpu_percent",
		"sentinel_network_packets_total", "sentinel_memory_page_faults_total",
	} {
		if !have[name] {
			t.Errorf("missing %s", name)
		}
	}
}

func TestOpenFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file-nr")
	if err := os.WriteFile(path, []byte("2944\t0\t9223372036854775807\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	open, max, ok := openFiles(path)
	if !ok || open != 2944 || max != 9223372036854775807 {
		t.Errorf("openFiles = %v, %v, %v", open, max, ok)
	}
	if _, _, ok := openFiles(filepath.Join(t.TempDir(), "missing")); ok {
		t.Error("a missing file should not be ok")
	}
}
