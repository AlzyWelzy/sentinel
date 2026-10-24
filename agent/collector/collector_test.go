//go:build linux || darwin || freebsd || openbsd || netbsd || windows

package collector

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
)

func TestVirtualInterfaces(t *testing.T) {
	for _, name := range []string{
		"lo", "docker0", "docker_gwbridge", "veth1a2b", "br-0c1d", "cali123", "lo0",
		"epair0b", "pflog0", "Loopback Pseudo-Interface 1", "vEthernet (WSL)", "isatap.{1234}",
	} {
		if !virtualInterface(name) {
			t.Errorf("%s should be skipped", name)
		}
	}
	for _, name := range []string{
		"eth0", "ens18", "eno1", "enp3s0", "wlan0", "en0", "bond0",
		"vtnet0", "em0", "igb0", "lagg0", "Ethernet", "Ethernet 2", "Wi-Fi",
	} {
		if virtualInterface(name) {
			t.Errorf("%s should be reported", name)
		}
	}
}

// Every sample must pass ingest's validation (ingest/vm.go), or it's dropped server-side.
func TestCollectProducesValidSamples(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	samples, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, s := range samples {
		names[s.Name] = true
		if !strings.HasPrefix(s.Name, "pulsegrid_") {
			t.Errorf("metric outside namespace: %s", s.Name)
		}
		for k := range s.Labels {
			if k == "tenant_id" || k == "host_id" {
				t.Errorf("%s sets reserved label %s", s.Name, k)
			}
		}
	}
	for _, want := range []string{"pulsegrid_cpu_usage_percent", "pulsegrid_memory_used_percent", "pulsegrid_load"} {
		if !names[want] {
			t.Errorf("missing %s", want)
		}
	}
}

// The first collection right after start must measure a real window, not the
// few milliseconds since priming (which reads as 0% or 50% on a 2-CPU host).
func TestFirstCPUSampleUsesARealWindow(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < minCPUWindow {
		t.Fatalf("first collect measured only %v of CPU time", elapsed)
	}
}

func TestOpticalAndPseudoFilesystemsIgnored(t *testing.T) {
	for _, fs := range []string{"CDFS", "UDF", "iso9660", "tmpfs", "devfs", "procfs", "overlay"} {
		if !ignoredFS(fs) {
			t.Errorf("%s should be ignored", fs)
		}
	}
	for _, fs := range []string{"NTFS", "ext4", "xfs", "zfs", "ufs", "ffs", "apfs", "btrfs"} {
		if ignoredFS(fs) {
			t.Errorf("%s should be reported", fs)
		}
	}
}

func TestBusyPercent(t *testing.T) {
	prev := cpu.TimesStat{User: 10, System: 10, Idle: 80, Irq: 5}
	// 10s on 1 CPU: 2 user, 3 system (of which 1 interrupt), 5 idle.
	cur := cpu.TimesStat{User: 12, System: 13, Idle: 85, Irq: 6}

	if got, _ := busyPercent(prev, cur, "windows"); got != 50 {
		t.Errorf("windows: got %.1f, want 50 (interrupts are inside system time)", got)
	}
	// Elsewhere irq is separate from system time, so it counts as busy.
	if got, _ := busyPercent(prev, cur, "linux"); got < 54.5 || got > 54.6 {
		t.Errorf("linux: got %.2f, want 54.55", got)
	}
	if _, ok := busyPercent(cur, cur, "linux"); ok {
		t.Error("no elapsed time must not produce a reading")
	}
}

func TestPlaceholderMachineIDsRejected(t *testing.T) {
	for _, id := range []string{
		"", "00000000-0000-0000-0000-000000000000", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
		"03000200-0400-0500-0006-000700080009", "  ",
	} {
		if usableID(id) {
			t.Errorf("%q accepted as a machine id", id)
		}
	}
	for _, id := range []string{"4c4c4544-0047-3510-8057-b4c04f4e3632", "a1b2c3d4e5f60718293a4b5c6d7e8f90"} {
		if !usableID(id) {
			t.Errorf("%q rejected", id)
		}
	}
}
