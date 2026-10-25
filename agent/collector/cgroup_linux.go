//go:build linux

package collector

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Containers (Docker, LXC, Kubernetes) and capped systemd units see the
// whole machine in /proc: 32 cores and 64 GB on a box that gives them one
// core and 1 GB. cgroup v2 holds the real limits. The agent walks up from
// its own cgroup and takes the tightest CPU quota and memory limit above
// it (its own unit's cgroup is skipped: a limit on the agent isn't a limit
// on the server).

var cgroupRoot = "/sys/fs/cgroup"
var procSelfCgroup = "/proc/self/cgroup"

type cgroupLimits struct {
	cores    float64 // CPU quota in cores; 0 = no quota
	cpuDir   string  // where the quota is, for cpu.stat
	memLimit uint64  // bytes; 0 = no limit
	memDir   string
}

func readTrim(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// ownCgroup is the agent's cgroup v2 path, e.g.
// /system.slice/docker-abc.scope/system.slice/pulsegrid-agent.service.
func ownCgroup() (string, bool) {
	f, err := os.Open(procSelfCgroup)
	if err != nil {
		return "", false
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if p, ok := strings.CutPrefix(s.Text(), "0::"); ok {
			return p, true
		}
	}
	return "", false
}

func detectLimits(hostCores int, hostMem uint64) cgroupLimits {
	var out cgroupLimits
	own, ok := ownCgroup()
	if !ok {
		return out
	}
	for dir := filepath.Dir(own); ; dir = filepath.Dir(dir) {
		full := filepath.Join(cgroupRoot, dir)
		if v, ok := readTrim(filepath.Join(full, "cpu.max")); ok {
			if f := strings.Fields(v); len(f) == 2 && f[0] != "max" {
				quota, e1 := strconv.ParseFloat(f[0], 64)
				period, e2 := strconv.ParseFloat(f[1], 64)
				if e1 == nil && e2 == nil && period > 0 {
					if c := quota / period; c > 0 && (out.cores == 0 || c < out.cores) {
						out.cores, out.cpuDir = c, full
					}
				}
			}
		}
		if v, ok := readTrim(filepath.Join(full, "memory.max")); ok && v != "max" {
			if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 && (out.memLimit == 0 || n < out.memLimit) {
				out.memLimit, out.memDir = n, full
			}
		}
		if dir == "/" || dir == "." {
			break
		}
	}
	// A "limit" at or above the machine's size isn't one.
	if hostCores > 0 && out.cores >= float64(hostCores) {
		out.cores, out.cpuDir = 0, ""
	}
	if hostMem > 0 && out.memLimit >= hostMem {
		out.memLimit, out.memDir = 0, ""
	}
	return out
}

// memoryUsed is what the kernel would not give back easily: current usage
// minus the inactive page cache, the same idea as "available" on a host.
func memoryUsed(dir string) (uint64, bool) {
	v, ok := readTrim(filepath.Join(dir, "memory.current"))
	if !ok {
		return 0, false
	}
	current, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, false
	}
	if stat, ok := readTrim(filepath.Join(dir, "memory.stat")); ok {
		for _, line := range strings.Split(stat, "\n") {
			if f := strings.Fields(line); len(f) == 2 && f[0] == "inactive_file" {
				if n, err := strconv.ParseUint(f[1], 10, 64); err == nil && n <= current {
					current -= n
				}
			}
		}
	}
	return current, true
}

func cpuUsageMicros(dir string) (uint64, bool) {
	stat, ok := readTrim(filepath.Join(dir, "cpu.stat"))
	if !ok {
		return 0, false
	}
	for _, line := range strings.Split(stat, "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "usage_usec" {
			n, err := strconv.ParseUint(f[1], 10, 64)
			return n, err == nil
		}
	}
	return 0, false
}

// cgroupCPU turns cpu.stat deltas into percent of the quota.
type cgroupCPU struct {
	usage uint64
	at    time.Time
}

func (c *cgroupCPU) percent(lim cgroupLimits, now time.Time) (float64, bool) {
	if lim.cores == 0 {
		return 0, false
	}
	usage, ok := cpuUsageMicros(lim.cpuDir)
	if !ok {
		return 0, false
	}
	prev := *c
	c.usage, c.at = usage, now
	if prev.at.IsZero() || usage < prev.usage {
		return 0, false
	}
	wall := now.Sub(prev.at).Seconds()
	if wall <= 0 {
		return 0, false
	}
	pct := float64(usage-prev.usage) / 1e6 / (wall * lim.cores) * 100
	if pct > 100 {
		pct = 100
	}
	return pct, true
}
