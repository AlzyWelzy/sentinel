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
		"pulsegrid_memory_bytes", "pulsegrid_disk_total_bytes", "pulsegrid_disk_used_bytes",
		"pulsegrid_procs", "pulsegrid_context_switches_total", "pulsegrid_interrupts_total",
		"pulsegrid_tcp_connections", "pulsegrid_threads_total", "pulsegrid_user_cpu_percent",
		"pulsegrid_network_packets_total", "pulsegrid_memory_page_faults_total",
	} {
		if !have[name] {
			t.Errorf("missing %s", name)
		}
	}
}
