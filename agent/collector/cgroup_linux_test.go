//go:build linux

package collector

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fakeCgroups(t *testing.T) string {
	root := t.TempDir()
	cgroupRoot, procSelfCgroup = filepath.Join(root, "cg"), filepath.Join(root, "self")
	t.Cleanup(func() { cgroupRoot, procSelfCgroup = "/sys/fs/cgroup", "/proc/self/cgroup" })
	writeFile(t, procSelfCgroup, "0::/system.slice/docker-1.scope/system.slice/pulsegrid-agent.service\n")
	ctr := filepath.Join(cgroupRoot, "system.slice/docker-1.scope")
	writeFile(t, filepath.Join(ctr, "cpu.max"), "150000 100000\n")
	writeFile(t, filepath.Join(ctr, "memory.max"), "1073741824\n")
	writeFile(t, filepath.Join(ctr, "memory.current"), "600000000\n")
	writeFile(t, filepath.Join(ctr, "memory.stat"), "anon 400000000\ninactive_file 100000000\n")
	writeFile(t, filepath.Join(ctr, "cpu.stat"), "usage_usec 1000000\n")
	// The agent's own unit is capped too: that must not count.
	own := filepath.Join(ctr, "system.slice/pulsegrid-agent.service")
	writeFile(t, filepath.Join(own, "memory.max"), "268435456\n")
	writeFile(t, filepath.Join(cgroupRoot, "system.slice/cpu.max"), "max 100000\n")
	return ctr
}

func TestDetectLimits(t *testing.T) {
	ctr := fakeCgroups(t)
	lim := detectLimits(32, 64<<30)
	if lim.cores != 1.5 || lim.memLimit != 1<<30 || lim.memDir != ctr {
		t.Fatalf("got %+v", lim)
	}
	if used, ok := memoryUsed(lim.memDir); !ok || used != 500000000 {
		t.Fatalf("memory used %d %v", used, ok)
	}
	// Limits at or above the host's size are no limits.
	if lim := detectLimits(1, 512<<20); lim.cores != 0 || lim.memLimit != 0 {
		t.Fatalf("got %+v", lim)
	}
}

func TestCgroupCPUPercent(t *testing.T) {
	ctr := fakeCgroups(t)
	lim := detectLimits(32, 64<<30)
	var c cgroupCPU
	t0 := time.Now()
	if _, ok := c.percent(lim, t0); ok {
		t.Fatal("first read has no baseline")
	}
	// 0.75 CPU-seconds over one second, against a 1.5-core quota: 50%.
	writeFile(t, filepath.Join(ctr, "cpu.stat"), "usage_usec 1750000\n")
	pct, ok := c.percent(lim, t0.Add(time.Second))
	if !ok || pct < 49.9 || pct > 50.1 {
		t.Fatalf("got %v %v", pct, ok)
	}
}

func TestNoCgroupFile(t *testing.T) {
	fakeCgroups(t)
	procSelfCgroup = "/nonexistent"
	if lim := detectLimits(4, 8<<30); lim.cores != 0 || lim.memLimit != 0 {
		t.Fatalf("got %+v", lim)
	}
}
