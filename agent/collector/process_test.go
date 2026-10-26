//go:build linux || darwin || freebsd || openbsd || netbsd || windows

package collector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/net"
)

func TestParsePS(t *testing.T) {
	out := []byte("Ss init 0.0 1024\nI nginx 10.0 2048\nS nginx 30.0 2048\nS my daemon 4.0 100\nZ sleep 0.0 0\nbad line\n")
	usage, total, ok := parsePS(out, 2)
	if !ok || total != 4 {
		t.Fatalf("total=%d ok=%v", total, ok)
	}
	n := usage["nginx"]
	if n.count != 2 || n.cpu != 20 || n.memory != 4096*1024 {
		t.Errorf("nginx = %+v; want 2 processes, 20%% of 2 CPUs, 4 MiB", *n)
	}
	if usage["my daemon"] == nil {
		t.Error("names with spaces must survive")
	}
	if usage["sleep"] != nil {
		t.Error("zombies aren't running")
	}
}

func TestTopByCPUAndMemory(t *testing.T) {
	usage := map[string]*procUsage{
		"a": {name: "a", cpu: 50, memory: 1},
		"b": {name: "b", cpu: 40, memory: 2},
		"c": {name: "c", cpu: 0, memory: 900},
		"d": {name: "d", cpu: 0, memory: 0},
	}
	got := []string{}
	for _, u := range topByCPUAndMemory(usage, 2) {
		got = append(got, u.name)
	}
	if strings.Join(got, ",") != "a,b,c" {
		t.Errorf("got %v; want the 2 busiest (a,b), then the largest not already listed (c)", got)
	}
}

func TestSameProcess(t *testing.T) {
	if !sameProcess("nginx.exe", "NGINX") || !sameProcess("sqlservr", "sqlservr.exe") {
		t.Error("case and .exe must not matter")
	}
	if sameProcess("nginx-debug", "nginx") {
		t.Error("only whole names match")
	}
}

func TestModePercents(t *testing.T) {
	prev := cpu.TimesStat{User: 10, System: 10, Idle: 70, Iowait: 5, Steal: 5}
	cur := cpu.TimesStat{User: 20, System: 15, Idle: 130, Iowait: 15, Steal: 20}
	m := modePercents(prev, cur, "linux")
	// Deltas: user 10, system 5, idle 60, iowait 10, steal 15 = 100.
	for mode, want := range map[string]float64{"user": 10, "system": 5, "idle": 60, "iowait": 10, "steal": 15} {
		if m[mode] != want {
			t.Errorf("%s = %.1f, want %.1f", mode, m[mode], want)
		}
	}
	if _, ok := modePercents(prev, cur, "windows")["iowait"]; ok {
		t.Error("windows doesn't account iowait; it must not be reported")
	}
}

func TestBlockDeviceFilter(t *testing.T) {
	for _, name := range []string{"loop0", "dm-0", "md127", "sr0", "zram0", "cd0", "pass1"} {
		if physicalDisk(name, "freebsd") {
			t.Errorf("%s should be skipped", name)
		}
	}
	for _, name := range []string{"ada0", "vtbd0", "nvd0", "C:", "sd0"} {
		if !physicalDisk(name, "freebsd") {
			t.Errorf("%s should be reported", name)
		}
	}
}

func TestServiceNames(t *testing.T) {
	for _, n := range []string{"nginx", "php8.2-fpm", "getty@tty1.service", "MSSQL$SQLEXPRESS"[:5], "W3SVC", "Some Service"} {
		if !validServiceName(n) {
			t.Errorf("%q rejected", n)
		}
	}
	for _, n := range []string{"", "-h", "--help", "a/b", "a;b", "$(x)", strings.Repeat("a", 101)} {
		if validServiceName(n) {
			t.Errorf("%q accepted", n)
		}
	}
}

func TestInterfaceIPs(t *testing.T) {
	ifaces := net.InterfaceStatList{
		{Name: "lo", Addrs: net.InterfaceAddrList{{Addr: "127.0.0.1/8"}}},
		{Name: "docker0", Addrs: net.InterfaceAddrList{{Addr: "172.17.0.1/16"}}},
		{Name: "eth0", Addrs: net.InterfaceAddrList{
			{Addr: "fe80::1/64"}, {Addr: "2001:db8::5/64"}, {Addr: "103.129.97.14/24"},
		}},
	}
	got := strings.Join(interfaceIPs(ifaces), ",")
	if got != "103.129.97.14,2001:db8::5" {
		t.Errorf("got %s", got)
	}
}

// A watched process that's running counts its processes; one that isn't
// reports 0, which is what "process down" alerts need.
func TestWatchedProcesses(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	self := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
	c.Watch([]string{self, "no-such-process-pulsegrid"}, nil)
	samples, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]float64{}
	for _, s := range samples {
		if s.Name == "pulsegrid_watched_process_count" {
			counts[s.Labels["process"]] = s.Value
		}
	}
	if counts["no-such-process-pulsegrid"] != 0 {
		t.Errorf("missing process: %v", counts)
	}
	if _, reported := counts["no-such-process-pulsegrid"]; !reported {
		t.Error("an absent watched process must report 0, not nothing")
	}
	// Process names are truncated on some systems (15 characters on Linux).
	if len(self) <= 15 && counts[self] < 1 {
		t.Errorf("the test binary %q should be running: %v", self, counts)
	}
}

func TestGroupName(t *testing.T) {
	for in, want := range map[string]string{
		"kworker/0:2-ata_sff": "kworker", "ksoftirqd/3": "ksoftirqd", "irq/24-virtio0": "irq",
		"scsi_eh_0": "scsi_eh", "nginx": "nginx", "php-fpm8.2": "php-fpm8.2",
	} {
		if got := groupName(in); got != want {
			t.Errorf("groupName(%q) = %q, want %q", in, got, want)
		}
	}
}
