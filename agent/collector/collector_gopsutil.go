//go:build linux || darwin || freebsd || openbsd || netbsd || windows

// gopsutil covers these platforms; per-OS differences (interface names,
// pseudo-filesystems, where the machine id lives) are handled below. darwin
// builds so the agent can run on a developer's Mac.

package collector

import (
	"context"
	"math"
	stdnet "net"
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
	last   cpuSnapshot
	lastAt time.Time
	procs  processTracker
	// Process and service names to report on, from the agent's config.
	watchProcesses []string
	watchServices  []string
	// In a container or a capped unit: CPU against the quota, not the host.
	cgCPU cgroupCPU
}

// cpuSnapshot is one read of the CPU counters: the machine total and, where
// the OS provides them, each core.
type cpuSnapshot struct {
	total cpu.TimesStat
	cores []cpu.TimesStat
}

// minCPUWindow: CPU counters advance in clock ticks, so a window much shorter
// than this measures a tick or two (a 2-CPU host reads 0% or 50%).
const minCPUWindow = time.Second

// maxCores caps per-core series; past this the chart is unreadable anyway.
const maxCores = 256

func New() (Collector, error) { return &gopsutilCollector{}, nil }

func (c *gopsutilCollector) Watch(processes, services []string) {
	c.watchProcesses, c.watchServices = processes, services
}

// cpuSamples measures busy time over total time since the previous sample,
// from the raw counters rather than gopsutil's Percent: on Windows that
// counts interrupt time twice and reads ~10 points high. The first sample
// after start measures a short real window instead of everything since boot.
func (c *gopsutilCollector) cpuSamples(ctx context.Context) []proto.Sample {
	if c.lastAt.IsZero() {
		snap, ok := readCPU(ctx)
		if !ok {
			return nil // no baseline yet: skip CPU this tick
		}
		c.last, c.lastAt = snap, time.Now()
	}
	if wait := minCPUWindow - time.Since(c.lastAt); wait > 0 {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
	snap, ok := readCPU(ctx)
	if !ok {
		// Keep the old baseline; the next successful read covers both ticks.
		return nil
	}
	prev := c.last
	c.last, c.lastAt = snap, time.Now()

	pct, ok := busyPercent(prev.total, snap.total, runtime.GOOS)
	if !ok {
		return nil
	}
	out := []proto.Sample{sample("pulsegrid_cpu_usage_percent", pct)}
	for mode, v := range modePercents(prev.total, snap.total, runtime.GOOS) {
		out = append(out, sample("pulsegrid_cpu_mode_percent", v, "mode", mode))
	}
	// Cores only when both reads have the same set (CPU hotplug changes it).
	if len(prev.cores) == len(snap.cores) {
		for i := range snap.cores {
			if p, ok := busyPercent(prev.cores[i], snap.cores[i], runtime.GOOS); ok {
				out = append(out, sample("pulsegrid_cpu_core_usage_percent", p, "core", strconv.Itoa(i)))
			}
		}
	}
	return out
}

// readCPU retries a failed read: on OpenBSD gopsutil intermittently returns
// "errno 0" (no real error), and a missed baseline must never turn into a
// since-boot average. Cores are best effort.
func readCPU(ctx context.Context) (cpuSnapshot, bool) {
	var snap cpuSnapshot
	ok := false
	for range 3 {
		if t, err := cpu.TimesWithContext(ctx, false); err == nil && len(t) == 1 {
			snap.total, ok = t[0], true
			break
		}
	}
	if !ok {
		return snap, false
	}
	if cores, err := cpu.TimesWithContext(ctx, true); err == nil && len(cores) > 1 {
		snap.cores = cores[:min(len(cores), maxCores)]
	}
	return snap, true
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

// modePercents splits the window into where the time went. Only the modes an
// OS actually accounts are reported: iowait, steal and softirq exist on
// Linux; Windows folds interrupts into system time. Steal is the share a
// hypervisor gave to other guests, the clearest sign of a noisy neighbour.
func modePercents(prev, cur cpu.TimesStat, goos string) map[string]float64 {
	d := func(a, b float64) float64 { return max(0, b-a) }
	modes := map[string]float64{
		"user":   d(prev.User, cur.User),
		"system": d(prev.System, cur.System),
		"idle":   d(prev.Idle, cur.Idle),
	}
	if goos != "windows" {
		modes["nice"] = d(prev.Nice, cur.Nice)
		modes["irq"] = d(prev.Irq, cur.Irq)
	}
	if goos == "linux" {
		modes["iowait"] = d(prev.Iowait, cur.Iowait)
		modes["steal"] = d(prev.Steal, cur.Steal)
		modes["softirq"] = d(prev.Softirq, cur.Softirq)
	}
	total := 0.0
	for _, v := range modes {
		total += v
	}
	if total <= 0 {
		return nil
	}
	for k, v := range modes {
		modes[k] = 100 * v / total
	}
	return modes
}

func (c *gopsutilCollector) Collect(ctx context.Context) ([]proto.Sample, error) {
	var out []proto.Sample

	out = append(out, c.cpuSamples(ctx)...)

	vm, vmErr := mem.VirtualMemoryWithContext(ctx)
	var hostMem uint64
	if vmErr == nil {
		hostMem = vm.Total
	}
	lim := detectLimits(runtime.NumCPU(), hostMem)
	if pct, ok := c.cgCPU.percent(lim, time.Now()); ok {
		for i := range out {
			if out[i].Name == "pulsegrid_cpu_usage_percent" {
				out[i].Value = pct
			}
		}
	}
	if used, ok := memoryUsed(lim.memDir); ok && lim.memLimit > 0 {
		if used > lim.memLimit {
			used = lim.memLimit
		}
		out = append(out,
			sample("pulsegrid_memory_used_percent", float64(used)/float64(lim.memLimit)*100),
			sample("pulsegrid_memory_total_bytes", float64(lim.memLimit)),
			sample("pulsegrid_memory_available_bytes", float64(lim.memLimit-used)),
		)
	} else if vmErr == nil {
		out = append(out,
			sample("pulsegrid_memory_used_percent", vm.UsedPercent),
			sample("pulsegrid_memory_total_bytes", float64(vm.Total)),
			sample("pulsegrid_memory_available_bytes", float64(vm.Available)),
		)
	}
	sw, swErr := mem.SwapMemoryWithContext(ctx)
	if swErr == nil && sw.Total > 0 {
		out = append(out, sample("pulsegrid_swap_used_percent", sw.UsedPercent))
	}
	if vmErr == nil && lim.memLimit == 0 {
		if swErr != nil {
			sw = nil
		}
		out = append(out, memoryDetail(vm, sw)...)
	}
	out = append(out, systemActivity(ctx)...)

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

	out = append(out, diskIOSamples(ctx)...)

	if nics, err := net.IOCountersWithContext(ctx, true); err == nil {
		for _, n := range nics {
			if virtualInterface(n.Name) {
				continue
			}
			out = append(out,
				sample("pulsegrid_network_bytes_total", float64(n.BytesRecv), "interface", n.Name, "direction", "rx"),
				sample("pulsegrid_network_bytes_total", float64(n.BytesSent), "interface", n.Name, "direction", "tx"),
				sample("pulsegrid_network_packets_total", float64(n.PacketsRecv), "interface", n.Name, "direction", "rx"),
				sample("pulsegrid_network_packets_total", float64(n.PacketsSent), "interface", n.Name, "direction", "tx"),
				sample("pulsegrid_network_errors_total", float64(n.Errin), "interface", n.Name, "direction", "rx"),
				sample("pulsegrid_network_errors_total", float64(n.Errout), "interface", n.Name, "direction", "tx"),
				sample("pulsegrid_network_drops_total", float64(n.Dropin), "interface", n.Name, "direction", "rx"),
				sample("pulsegrid_network_drops_total", float64(n.Dropout), "interface", n.Name, "direction", "tx"),
			)
			if up, speed, ok := linkInfo(n.Name); runtime.GOOS == "linux" {
				out = append(out, sample("pulsegrid_network_up", up, "interface", n.Name))
				if ok {
					out = append(out, sample("pulsegrid_network_speed_mbps", speed, "interface", n.Name))
				}
			}
		}
	}

	if up, err := host.UptimeWithContext(ctx); err == nil {
		out = append(out, sample("pulsegrid_uptime_seconds", float64(up)))
	}

	out = append(out, c.processSamples(ctx)...)
	out = append(out, serviceSamples(ctx, c.watchServices)...)
	return out, nil
}

func diskSamples(mountpoint, device string, u *disk.UsageStat) []proto.Sample {
	out := []proto.Sample{
		sample("pulsegrid_disk_used_percent", u.UsedPercent, "mountpoint", mountpoint, "device", device),
		sample("pulsegrid_disk_free_bytes", float64(u.Free), "mountpoint", mountpoint, "device", device),
		sample("pulsegrid_disk_total_bytes", float64(u.Total), "mountpoint", mountpoint, "device", device, "fstype", u.Fstype),
		sample("pulsegrid_disk_used_bytes", float64(u.Used), "mountpoint", mountpoint, "device", device),
	}
	// Filesystems without a fixed inode table (NTFS, ZFS, btrfs) report 0.
	if u.InodesTotal > 0 {
		out = append(out, sample("pulsegrid_disk_inodes_used_percent", u.InodesUsedPercent,
			"mountpoint", mountpoint, "device", device))
	}
	return out
}

// Block devices that aren't real disks, or are layered on disks already
// counted (device-mapper, md RAID, partitions), so counting them would
// double the host's I/O.
var ignoredBlockDevicePrefixes = []string{
	"loop", "ram", "zram", "sr", "fd", "nbd", "dm-", "md", // Linux
	"cd", "pass", // BSD
}

// diskIOSamples reports cumulative I/O counters per physical disk; the
// dashboard turns them into rates. Busy time (the share of time the disk had
// requests in flight) is only accounted on Linux and FreeBSD.
func diskIOSamples(ctx context.Context) []proto.Sample {
	counters, err := disk.IOCountersWithContext(ctx)
	if err != nil {
		return nil
	}
	busyTime := runtime.GOOS == "linux" || runtime.GOOS == "freebsd"
	var out []proto.Sample
	for name, c := range counters {
		if !physicalDisk(name, runtime.GOOS) {
			continue
		}
		out = append(out,
			sample("pulsegrid_disk_read_bytes_total", float64(c.ReadBytes), "device", name),
			sample("pulsegrid_disk_written_bytes_total", float64(c.WriteBytes), "device", name),
			sample("pulsegrid_disk_reads_total", float64(c.ReadCount), "device", name),
			sample("pulsegrid_disk_writes_total", float64(c.WriteCount), "device", name),
		)
		if busyTime {
			out = append(out, sample("pulsegrid_disk_io_time_seconds_total", float64(c.IoTime)/1000, "device", name))
		}
		// Time spent on reads and writes (latency = time / operations) and the
		// weighted I/O time (its rate is the average queue length).
		if c.ReadTime > 0 || c.WriteTime > 0 {
			out = append(out,
				sample("pulsegrid_disk_read_time_seconds_total", float64(c.ReadTime)/1000, "device", name),
				sample("pulsegrid_disk_write_time_seconds_total", float64(c.WriteTime)/1000, "device", name),
			)
		}
		if c.WeightedIO > 0 {
			out = append(out, sample("pulsegrid_disk_weighted_io_seconds_total", float64(c.WeightedIO)/1000, "device", name))
		}
	}
	return out
}

func physicalDisk(name, goos string) bool {
	for _, p := range ignoredBlockDevicePrefixes {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	if goos == "linux" {
		// Whole disks have a /sys/block entry; partitions (sda1, nvme0n1p2) don't.
		_, err := os.Stat("/sys/block/" + name)
		return err == nil
	}
	return true
}

// maxIPs caps the addresses reported; a host with dozens is a router or a
// container host, and the first few identify it.
const maxIPs = 16

// Meta describes the machine as it is now: hostname, OS version, addresses
// on its real interfaces, CPU count and memory.
func Meta(ctx context.Context) proto.HostMeta {
	var m proto.HostMeta
	if h, err := host.InfoWithContext(ctx); err == nil {
		m.Hostname, m.PlatformVersion = h.Hostname, h.PlatformVersion
	}
	m.CPUCores = runtime.NumCPU()
	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		m.MemoryBytes = vm.Total
	}
	// A container's size is its limits.
	lim := detectLimits(m.CPUCores, m.MemoryBytes)
	if lim.cores > 0 {
		m.CPUCores = int(math.Ceil(lim.cores))
	}
	if lim.memLimit > 0 {
		m.MemoryBytes = lim.memLimit
	}
	if ifaces, err := net.InterfacesWithContext(ctx); err == nil {
		m.IPAddresses = interfaceIPs(ifaces)
	}
	return m
}

// interfaceIPs returns global unicast addresses (IPv4 first) on interfaces
// that aren't loopback or container plumbing.
func interfaceIPs(ifaces net.InterfaceStatList) []string {
	var v4, v6 []string
	for _, iface := range ifaces {
		if virtualInterface(iface.Name) {
			continue
		}
		for _, a := range iface.Addrs {
			ip, _, err := stdnet.ParseCIDR(a.Addr)
			if err != nil || !ip.IsGlobalUnicast() {
				continue
			}
			if ip.To4() != nil {
				v4 = append(v4, ip.String())
			} else {
				v6 = append(v6, ip.String())
			}
		}
	}
	all := append(v4, v6...)
	return all[:min(len(all), maxIPs)]
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
