//go:build linux

package collector

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/AlzyWelzy/sentinel/proto"
)

// procRoot honours HOST_PROC (the agent in a container watching its host).
func procRoot() string {
	if p := os.Getenv("HOST_PROC"); p != "" {
		return p
	}
	return "/proc"
}

func sysRoot() string {
	if p := os.Getenv("HOST_SYS"); p != "" {
		return p
	}
	return "/sys"
}

func runRoot() string {
	if p := os.Getenv("HOST_RUN"); p != "" {
		return p
	}
	return "/run"
}

// loggedInSessions counts open login sessions from systemd-logind, which
// newer distributions keep instead of utmp. ok is false without logind.
func loggedInSessions(dir string) (n int, ok bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, false
	}
	for _, e := range entries {
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		class, state := "", ""
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if v, found := strings.CutPrefix(sc.Text(), "CLASS="); found {
				class = v
			} else if v, found := strings.CutPrefix(sc.Text(), "STATE="); found {
				state = v
			}
		}
		f.Close()
		if class == "user" && state != "closing" {
			n++
		}
	}
	return n, true
}

func platformUsers() (int, bool) {
	return loggedInSessions(filepath.Join(runRoot(), "systemd", "sessions"))
}

// TCP states as /proc/net/tcp numbers them.
var tcpStates = map[string]string{
	"01": "established", "02": "syn_sent", "03": "syn_recv", "04": "fin_wait1",
	"05": "fin_wait2", "06": "time_wait", "07": "close", "08": "close_wait",
	"09": "last_ack", "0A": "listen", "0B": "closing",
}

func platformActivity() []proto.Sample {
	var out []proto.Sample
	root := procRoot()
	if n, ok := interrupts(filepath.Join(root, "stat")); ok {
		out = append(out, sample("sentinel_interrupts_total", n))
	}
	counts := map[string]int{}
	for _, f := range []string{"net/tcp", "net/tcp6"} {
		countTCP(filepath.Join(root, f), counts)
	}
	for state, n := range counts {
		out = append(out, sample("sentinel_tcp_connections", float64(n), "state", state))
	}
	for _, res := range []string{"cpu", "memory", "io"} {
		out = append(out, pressure(filepath.Join(root, "pressure", res), res)...)
	}
	if open, max, ok := openFiles(filepath.Join(root, "sys", "fs", "file-nr")); ok {
		out = append(out, sample("sentinel_open_files", open))
		if max > 0 && max < 1<<40 { // newer kernels report a meaningless 2^63-1
			out = append(out, sample("sentinel_open_files_limit", max))
		}
	}
	return out
}

// openFiles reads /proc/sys/fs/file-nr: file handles allocated, allocated
// but unused (always 0 since Linux 2.6), and the system-wide maximum.
func openFiles(path string) (open, max float64, ok bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false
	}
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return 0, 0, false
	}
	alloc, err1 := strconv.ParseFloat(f[0], 64)
	unused, err2 := strconv.ParseFloat(f[1], 64)
	limit, err3 := strconv.ParseFloat(f[2], 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return 0, 0, false
	}
	return alloc - unused, limit, true
}

// interrupts is the total from /proc/stat's "intr" line.
func interrupts(path string) (float64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 1<<20)
	for s.Scan() {
		if fields := strings.Fields(s.Text()); len(fields) > 1 && fields[0] == "intr" {
			n, err := strconv.ParseFloat(fields[1], 64)
			return n, err == nil
		}
	}
	return 0, false
}

func countTCP(path string, counts map[string]int) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Scan() // header
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) > 3 {
			if state, ok := tcpStates[strings.ToUpper(fields[3])]; ok {
				counts[state]++
			}
		}
	}
}

// pressure reads one PSI file: "some avg10=0.12 avg60=0.05 avg300=0.01 total=..."
// (and "full" for memory and io), reporting the 60 s and 300 s averages.
func pressure(path, resource string) []proto.Sample {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parsePressure(string(b), resource)
}

func parsePressure(text, resource string) []proto.Sample {
	var out []proto.Sample
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kind := fields[0]
		for _, f := range fields[1:] {
			k, v, ok := strings.Cut(f, "=")
			if !ok || (k != "avg60" && k != "avg300") {
				continue
			}
			if n, err := strconv.ParseFloat(v, 64); err == nil {
				out = append(out, sample("sentinel_pressure_percent", n,
					"resource", resource, "kind", kind, "window", strings.TrimPrefix(k, "avg")))
			}
		}
	}
	return out
}

// linkInfo: an interface's state (1 up) and speed in Mbit/s, when known.
func linkInfo(name string) (up float64, speed float64, haveSpeed bool) {
	dir := filepath.Join(sysRoot(), "class", "net", name)
	if b, err := os.ReadFile(filepath.Join(dir, "operstate")); err == nil {
		if strings.TrimSpace(string(b)) == "up" {
			up = 1
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "speed")); err == nil {
		if n, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64); err == nil && n > 0 {
			return up, n, true
		}
	}
	return up, 0, false
}
