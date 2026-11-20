//go:build linux || darwin || freebsd || openbsd || netbsd || windows

package collector

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"os/user"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/process"

	"github.com/AlzyWelzy/sentinel/proto"
)

// topProcesses is how many process names are reported by CPU and by memory
// (the two lists overlap, so usually fewer than twice this).
const topProcesses = 10

// processTracker remembers each process's CPU time so the next collection can
// turn it into a rate. Processes are told apart by pid and start time, so a
// reused pid doesn't inherit another process's counters.
type processTracker struct {
	last   map[int32]procTimes
	lastAt time.Time
	// From the last collection: zombies, threads, and usage per user.
	zombies int
	threads int
	users   map[string]*procUsage
	names   map[uint32]string // uid → user name, looked up once
	// The container's CPU quota in cores (0 = none), so a process's CPU is a
	// share of what this server may use, like its CPU usage.
	cores float64
}

type procTimes struct {
	created int64
	cpu     float64 // user+system seconds
}

// procUsage is one process name's total over all its processes.
type procUsage struct {
	name   string
	cpu    float64 // percent of the whole machine
	memory float64 // resident bytes
	count  int
}

// processSamples reports the busiest process names by CPU and by memory,
// grouped by name (a web server's 40 workers are one line), plus the count of
// every watched name, including zero.
func (c *gopsutilCollector) processSamples(ctx context.Context) []proto.Sample {
	usage, total, ok := c.procs.collect(ctx)
	if !ok {
		usage, total, ok = psUsage(ctx)
	}
	if !ok {
		return nil
	}
	out := []proto.Sample{sample("sentinel_processes_total", float64(total))}
	if runtime.GOOS != "windows" {
		out = append(out, sample("sentinel_procs", float64(c.procs.zombies), "state", "zombie"))
	}
	if c.procs.threads > 0 {
		out = append(out, sample("sentinel_threads_total", float64(c.procs.threads)))
	}
	for _, u := range topByCPUAndMemory(c.procs.users, topProcesses) {
		out = append(out,
			sample("sentinel_user_cpu_percent", u.cpu, "user", u.name),
			sample("sentinel_user_memory_bytes", u.memory, "user", u.name),
		)
	}
	for _, u := range topByCPUAndMemory(usage, topProcesses) {
		out = append(out,
			sample("sentinel_process_cpu_percent", u.cpu, "process", u.name),
			sample("sentinel_process_memory_bytes", u.memory, "process", u.name),
			sample("sentinel_process_count", float64(u.count), "process", u.name),
		)
	}
	for _, want := range c.watchProcesses {
		n := 0
		for _, u := range usage {
			if sameProcess(u.name, want) {
				n += u.count
			}
		}
		out = append(out, sample("sentinel_watched_process_count", float64(n), "process", want))
	}
	return out
}

func (t *processTracker) collect(ctx context.Context) (map[string]*procUsage, int, bool) {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, 0, false
	}
	now := time.Now()
	wall := now.Sub(t.lastAt).Seconds()
	cpus := effectiveCPUs(runtime.NumCPU(), t.cores)
	seen := make(map[int32]procTimes, len(procs))
	usage := map[string]*procUsage{}
	users := map[string]*procUsage{}
	zombies, threads := 0, 0
	if t.names == nil {
		t.names = map[uint32]string{}
	}
	for _, p := range procs {
		name, err := p.NameWithContext(ctx)
		if err != nil || name == "" {
			continue // exited, or not ours to read
		}
		if zombie(ctx, p) {
			zombies++
			continue // exited, waiting for its parent to reap it: not running
		}
		name = groupName(name)
		u := usage[name]
		if u == nil {
			u = &procUsage{name: name}
			usage[name] = u
		}
		u.count++
		owner := t.owner(ctx, p)
		byUser := users[owner]
		if byUser == nil {
			byUser = &procUsage{name: owner}
			users[owner] = byUser
		}
		byUser.count++
		if n, err := p.NumThreadsWithContext(ctx); err == nil {
			threads += int(n)
		}
		if m, err := p.MemoryInfoWithContext(ctx); err == nil {
			u.memory += float64(m.RSS)
			byUser.memory += float64(m.RSS)
		}
		times, err := p.TimesWithContext(ctx)
		if err != nil {
			continue
		}
		created, _ := p.CreateTimeWithContext(ctx)
		cur := procTimes{created: created, cpu: times.User + times.System}
		seen[p.Pid] = cur
		if prev, ok := t.last[p.Pid]; ok && prev.created == cur.created && wall > 0 {
			pct := max(0, cur.cpu-prev.cpu) / wall / cpus * 100
			u.cpu += pct
			byUser.cpu += pct
		}
	}
	t.last, t.lastAt = seen, now
	t.zombies, t.threads, t.users = zombies, threads, users
	return usage, len(procs), true
}

func zombie(ctx context.Context, p *process.Process) bool {
	if runtime.GOOS == "windows" {
		return false
	}
	status, err := p.StatusWithContext(ctx)
	return err == nil && len(status) > 0 && status[0] == process.Zombie
}

// effectiveCPUs is how many cores the server may use: its CPU quota when it
// has one below the host's core count, otherwise every core.
func effectiveCPUs(hostCPUs int, quota float64) float64 {
	if quota > 0 && quota < float64(hostCPUs) {
		return quota
	}
	return float64(hostCPUs)
}

// psUsage reads ps where gopsutil has no process support (NetBSD). %CPU from
// ps is a decaying average over about a minute, not the last interval, which
// is close enough for a top-processes list.
func psUsage(ctx context.Context) (map[string]*procUsage, int, bool) {
	if runtime.GOOS != "netbsd" {
		return nil, 0, false
	}
	out, err := exec.CommandContext(ctx, "/bin/ps", "-ax", "-o", "stat=", "-o", "comm=", "-o", "pcpu=", "-o", "rss=").Output()
	if err != nil {
		return nil, 0, false
	}
	return parsePS(out, float64(runtime.NumCPU()))
}

// parsePS parses `ps -o stat= -o comm= -o pcpu= -o rss=` (rss in KiB),
// skipping zombies (state Z). The name is everything between the state and
// the last two fields, since names can contain spaces.
func parsePS(out []byte, cpus float64) (map[string]*procUsage, int, bool) {
	usage := map[string]*procUsage{}
	total := 0
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || strings.HasPrefix(f[0], "Z") {
			continue
		}
		f = f[1:]
		pcpu, err1 := strconv.ParseFloat(f[len(f)-2], 64)
		rss, err2 := strconv.ParseFloat(f[len(f)-1], 64)
		if err1 != nil || err2 != nil {
			continue
		}
		name := groupName(strings.Join(f[:len(f)-2], " "))
		u := usage[name]
		if u == nil {
			u = &procUsage{name: name}
			usage[name] = u
		}
		u.count++
		u.cpu += pcpu / max(cpus, 1)
		u.memory += rss * 1024
		total++
	}
	return usage, total, total > 0
}

// Linux kernel threads named per CPU or per job (kworker/0:2-events,
// ksoftirqd/3, irq/24-virtio0) are grouped under the part before the slash.
var kernelThreadPrefixes = []string{"kworker/", "ksoftirqd/", "migration/", "cpuhp/", "idle_inject/", "irq/", "rcuop/", "rcuos/", "rcuog/", "kthrotld/", "scsi_eh_", "scsi_tmf_"}

func groupName(name string) string {
	for _, prefix := range kernelThreadPrefixes {
		if strings.HasPrefix(name, prefix) {
			return strings.TrimRight(prefix, "/_")
		}
	}
	return name
}

// topByCPUAndMemory returns the n busiest names by CPU together with the n
// largest by memory, without duplicates, busiest first.
func topByCPUAndMemory(usage map[string]*procUsage, n int) []*procUsage {
	all := make([]*procUsage, 0, len(usage))
	for _, u := range usage {
		all = append(all, u)
	}
	picked := map[string]bool{}
	var out []*procUsage
	take := func(less func(a, b *procUsage) bool, keep func(*procUsage) bool) {
		sort.Slice(all, func(i, j int) bool { return less(all[i], all[j]) })
		for _, u := range all[:min(n, len(all))] {
			if keep(u) && !picked[u.name] {
				picked[u.name] = true
				out = append(out, u)
			}
		}
	}
	byName := func(a, b *procUsage) bool { return a.name < b.name }
	take(func(a, b *procUsage) bool {
		if a.cpu != b.cpu {
			return a.cpu > b.cpu
		}
		return byName(a, b)
	}, func(u *procUsage) bool { return u.cpu > 0 })
	take(func(a, b *procUsage) bool {
		if a.memory != b.memory {
			return a.memory > b.memory
		}
		return byName(a, b)
	}, func(u *procUsage) bool { return u.memory > 0 })
	return out
}

// sameProcess compares names the way people type them: case-insensitively,
// with or without Windows' .exe.
func sameProcess(actual, want string) bool {
	trim := func(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".exe") }
	return trim(actual) == trim(want)
}

// owner is the user a process runs as (names cached by uid).
func (t *processTracker) owner(ctx context.Context, p *process.Process) string {
	uids, err := p.UidsWithContext(ctx)
	if err != nil || len(uids) == 0 {
		if name, err := p.UsernameWithContext(ctx); err == nil && name != "" {
			return name
		}
		return "unknown"
	}
	uid := uids[0]
	if name, ok := t.names[uid]; ok {
		return name
	}
	name := strconv.Itoa(int(uid))
	if u, err := user.LookupId(name); err == nil && u.Username != "" {
		name = u.Username
	}
	t.names[uid] = name
	return name
}
