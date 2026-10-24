//go:build linux || darwin || freebsd || openbsd || netbsd || windows

// gopsutil covers these platforms; per-OS differences (interface names,
// pseudo-filesystems, where the machine id lives) are handled below. darwin
// builds so the agent can run on a developer's Mac.

package collector

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"

	"github.com/example-org/pulsegrid/proto"
)

// Filesystems that don't represent real storage (Linux, then BSD).
var ignoredFSTypes = map[string]bool{
	"tmpfs": true, "devtmpfs": true, "overlay": true, "squashfs": true, "proc": true,
	"sysfs": true, "cgroup": true, "cgroup2": true, "devfs": true, "autofs": true,
	"nsfs": true, "tracefs": true, "debugfs": true, "fuse.lxcfs": true,
	"fdescfs": true, "procfs": true, "linprocfs": true, "linsysfs": true, "nullfs": true,
	"kernfs": true, "ptyfs": true, "mfs": true,
	// Optical media (Windows reports these upper-case) are always "100% full".
	"iso9660": true, "cdfs": true, "udf": true,
}

func ignoredFS(fstype string) bool { return ignoredFSTypes[strings.ToLower(fstype)] }

// Loopback and container/VM plumbing. Traffic on these also crosses a real
// interface, so counting them would double the host's network numbers.
var virtualInterfacePrefixes = []string{
	// Linux / containers
	"lo", "veth", "docker", "br-", "virbr", "cni", "flannel", "cali", "vxlan", "tunl",
	"kube-", "weave", "tap", "vnet",
	// macOS
	"utun", "awdl", "llw", "bridge", "anpi", "ap1", "gif", "stf",
	// BSD
	"epair", "pflog", "pfsync", "enc",
	// Windows
	"Loopback", "vEthernet", "isatap", "Teredo", "Local Area Connection*",
}

func virtualInterface(name string) bool {
	for _, p := range virtualInterfacePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

type gopsutilCollector struct {
	lastCPU   cpu.TimesStat
	lastCPUAt time.Time
}

// minCPUWindow: CPU counters advance in clock ticks, so a window much shorter
// than this measures a tick or two (a 2-CPU host reads 0% or 50%).
const minCPUWindow = time.Second

func New() (Collector, error) { return &gopsutilCollector{}, nil }

// cpuPercent is busy time over total time since the previous sample, from
// the raw counters rather than gopsutil's Percent: on Windows that counts
// interrupt time twice and reads ~10 points high. The first sample after
// start measures a short real window instead of everything since boot.
func (c *gopsutilCollector) cpuPercent(ctx context.Context) (float64, bool) {
	if c.lastCPUAt.IsZero() {
		t, ok := readCPUTimes(ctx)
		if !ok {
			return 0, false // no baseline yet: skip CPU this tick
		}
		c.lastCPU, c.lastCPUAt = t, time.Now()
	}
	if wait := minCPUWindow - time.Since(c.lastCPUAt); wait > 0 {
		select {
		case <-ctx.Done():
			return 0, false
		case <-time.After(wait):
		}
	}
	t, ok := readCPUTimes(ctx)
	if !ok {
		// Keep the old baseline; the next successful read covers both ticks.
		return 0, false
	}
	pct, ok := busyPercent(c.lastCPU, t, runtime.GOOS)
	c.lastCPU, c.lastCPUAt = t, time.Now()
	return pct, ok
}

// readCPUTimes retries a failed read: on OpenBSD gopsutil intermittently
// returns "errno 0" (no real error), and a missed baseline must never turn
// into a since-boot average.
func readCPUTimes(ctx context.Context) (cpu.TimesStat, bool) {
	for range 3 {
		if t, err := cpu.TimesWithContext(ctx, false); err == nil && len(t) == 1 {
			return t[0], true
		}
	}
	return cpu.TimesStat{}, false
}

// busyPercent compares two counter snapshots. Guest time is already inside
// user time on Linux, and on Windows kernel ("system") time already includes
// interrupt time, so neither is added again.
func busyPercent(prev, cur cpu.TimesStat, goos string) (float64, bool) {
	busyOf := func(t cpu.TimesStat) float64 {
		b := t.User + t.System + t.Nice + t.Softirq + t.Steal
		if goos != "windows" {
			b += t.Irq
		}
		return b
	}
	busy := busyOf(cur) - busyOf(prev)
	idle := (cur.Idle + cur.Iowait) - (prev.Idle + prev.Iowait)
	total := busy + idle
	if total <= 0 || busy < 0 {
		return 0, false
	}
	return min(100, 100*busy/total), true
}

func (c *gopsutilCollector) Collect(ctx context.Context) ([]proto.Sample, error) {
	var out []proto.Sample

	if pct, ok := c.cpuPercent(ctx); ok {
		out = append(out, sample("pulsegrid_cpu_usage_percent", pct))
	}

	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		out = append(out,
			sample("pulsegrid_memory_used_percent", vm.UsedPercent),
			sample("pulsegrid_memory_total_bytes", float64(vm.Total)),
			sample("pulsegrid_memory_available_bytes", float64(vm.Available)),
		)
	}
	if sw, err := mem.SwapMemoryWithContext(ctx); err == nil && sw.Total > 0 {
		out = append(out, sample("pulsegrid_swap_used_percent", sw.UsedPercent))
	}

	if avg, ok := loadAverage(ctx); ok {
		out = append(out,
			sample("pulsegrid_load", avg.Load1, "period", "1m"),
			sample("pulsegrid_load", avg.Load5, "period", "5m"),
			sample("pulsegrid_load", avg.Load15, "period", "15m"),
		)
	}

	disks := 0
	if parts, err := disk.PartitionsWithContext(ctx, false); err == nil {
		seen := map[string]bool{}
		for _, p := range parts {
			if ignoredFS(p.Fstype) || seen[p.Mountpoint] {
				continue
			}
			seen[p.Mountpoint] = true
			if u, err := disk.UsageWithContext(ctx, p.Mountpoint); err == nil && u.Total > 0 {
				out = append(out, diskSamples(p.Mountpoint, p.Device, u)...)
				disks++
			}
		}
	}
	// Containers (LXC, Docker-based servers) often have only an overlay root,
	// which is filtered above; report the root filesystem rather than nothing.
	if disks == 0 {
		if u, err := disk.UsageWithContext(ctx, "/"); err == nil && u.Total > 0 {
			out = append(out, diskSamples("/", u.Fstype, u)...)
		}
	}

	if nics, err := net.IOCountersWithContext(ctx, true); err == nil {
		for _, n := range nics {
			if virtualInterface(n.Name) {
				continue
			}
			out = append(out,
				sample("pulsegrid_network_bytes_total", float64(n.BytesRecv), "interface", n.Name, "direction", "rx"),
				sample("pulsegrid_network_bytes_total", float64(n.BytesSent), "interface", n.Name, "direction", "tx"),
			)
		}
	}

	if up, err := host.UptimeWithContext(ctx); err == nil {
		out = append(out, sample("pulsegrid_uptime_seconds", float64(up)))
	}
	return out, nil
}

func diskSamples(mountpoint, device string, u *disk.UsageStat) []proto.Sample {
	return []proto.Sample{
		sample("pulsegrid_disk_used_percent", u.UsedPercent, "mountpoint", mountpoint, "device", device),
		sample("pulsegrid_disk_free_bytes", float64(u.Free), "mountpoint", mountpoint, "device", device),
	}
}

func Info(ctx context.Context) (HostInfo, error) {
	h, err := host.InfoWithContext(ctx)
	if err != nil {
		return HostInfo{}, err
	}
	return HostInfo{
		MachineID:       machineID(h.HostID),
		Hostname:        h.Hostname,
		OS:              h.OS,
		Platform:        h.Platform,
		PlatformVersion: h.PlatformVersion,
		Arch:            runtime.GOARCH,
	}, nil
}

// machineID prefers a stable OS identifier that survives hostname changes and
// agent reinstalls, so re-registering updates the same host: systemd's
// machine-id on Linux, /etc/hostid on FreeBSD, and otherwise gopsutil's host
// id (the registry MachineGuid on Windows, the SMBIOS UUID elsewhere).
func machineID(fallback string) string {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id", "/etc/hostid"} {
		if b, err := os.ReadFile(path); err == nil {
			if id := strings.TrimSpace(string(b)); usableID(id) {
				return id
			}
		}
	}
	if usableID(fallback) {
		return fallback
	}
	// gopsutil has no host id on OpenBSD or NetBSD; their sysctls expose the
	// SMBIOS system UUID. Empty means the caller falls back to a stored id.
	for _, name := range []string{"hw.uuid", "machdep.dmi.system-uuid"} {
		if id := sysctl(name); usableID(id) {
			return id
		}
	}
	return ""
}

// usableID rejects the placeholder UUIDs many hypervisors and boards report
// (all zeros, all Fs, the well-known 03000200-... default). Two machines
// sharing one would register as a single host and overwrite each other.
func usableID(id string) bool {
	hex := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(id), "-", ""))
	switch {
	case hex == "", strings.Trim(hex, "0") == "", strings.Trim(hex, "f") == "":
		return false
	case hex == "03000200040005000006000700080009":
		return false
	}
	return true
}

// sysctl reads a value by full path: services and cron often run without
// /sbin in PATH.
func sysctl(name string) string {
	for _, bin := range []string{"/sbin/sysctl", "/usr/sbin/sysctl"} {
		if out, err := exec.Command(bin, "-n", name).Output(); err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	return ""
}

// loadAverage falls back to vm.loadavg where gopsutil has no implementation
// (NetBSD).
func loadAverage(ctx context.Context) (*load.AvgStat, bool) {
	if avg, err := load.AvgWithContext(ctx); err == nil {
		return avg, true
	}
	fields := strings.Fields(strings.Trim(sysctl("vm.loadavg"), "{} "))
	if len(fields) < 3 {
		return nil, false
	}
	var v [3]float64
	for i := range v {
		f, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return nil, false
		}
		v[i] = f
	}
	return &load.AvgStat{Load1: v[0], Load5: v[1], Load15: v[2]}, true
}
