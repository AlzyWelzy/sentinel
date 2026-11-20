package collector

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/AlzyWelzy/sentinel/proto"
)

const maxPackages = 5000

// Inventory gathers what's installed and listening. It shells out to the
// package manager, so it runs every few hours rather than every tick.
func Inventory(ctx context.Context) proto.Inventory {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var inv proto.Inventory
	if hi, err := host.InfoWithContext(ctx); err == nil {
		inv.KernelVersion = hi.KernelVersion
		inv.BootTime = int64(hi.BootTime)
		if hi.VirtualizationSystem != "" && hi.VirtualizationRole == "guest" {
			inv.Virtualization = hi.VirtualizationSystem
		}
	}
	if ci, err := cpu.InfoWithContext(ctx); err == nil && len(ci) > 0 {
		inv.CPUModel = strings.TrimSpace(ci[0].ModelName)
	}
	inv.Packages = packages(ctx)
	inv.ListeningPorts = listening(ctx)
	return inv
}

// packages asks whichever package manager is present.
func packages(ctx context.Context) []proto.Package {
	type source struct {
		bin  string
		args []string
		sep  string
	}
	var sources []source
	switch runtime.GOOS {
	case "linux":
		sources = []source{
			{"dpkg-query", []string{"-W", "-f=${binary:Package}\t${Version}\n"}, "\t"},
			{"rpm", []string{"-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"}, "\t"},
			{"apk", []string{"info", "-v"}, "apk"},
			{"pacman", []string{"-Q"}, " "},
		}
	case "freebsd":
		sources = []source{{"pkg", []string{"query", "%n\t%v"}, "\t"}}
	case "openbsd", "netbsd":
		sources = []source{{"pkg_info", []string{}, "pkg_info"}}
	case "darwin":
		sources = []source{{"brew", []string{"list", "--versions"}, " "}}
	case "windows":
		return windowsPackages(ctx)
	}
	for _, s := range sources {
		path, err := exec.LookPath(s.bin)
		if err != nil {
			continue
		}
		out, err := exec.CommandContext(ctx, path, s.args...).Output()
		if err != nil {
			continue
		}
		return parsePackages(out, s.sep)
	}
	return nil
}

func parsePackages(out []byte, sep string) []proto.Package {
	var pkgs []proto.Package
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() && len(pkgs) < maxPackages {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var name, ver string
		switch sep {
		case "apk", "pkg_info":
			// name-1.2.3-r0 (apk), or "name-1.2.3   description" (pkg_info)
			field := strings.Fields(line)[0]
			i := strings.LastIndex(field, "-")
			if sep == "apk" {
				// apk versions contain one dash (1.2.3-r0): split at the second-to-last.
				if j := strings.LastIndex(field[:max(i, 0)], "-"); j > 0 {
					i = j
				}
			}
			if i <= 0 {
				continue
			}
			name, ver = field[:i], field[i+1:]
		default:
			n, v, ok := strings.Cut(line, sep)
			if !ok {
				continue
			}
			name, ver = n, strings.TrimSpace(v)
		}
		pkgs = append(pkgs, proto.Package{Name: name, Version: ver})
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })
	return pkgs
}

// listening reports TCP sockets in LISTEN and bound UDP sockets. Without
// privileges, other users' process names aren't visible; the port still is.
func listening(ctx context.Context) []proto.ListenPort {
	conns, err := net.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		return nil
	}
	names := map[int32]string{}
	seen := map[string]bool{}
	var out []proto.ListenPort
	for _, c := range conns {
		var protocol string
		switch {
		case c.Type == 1 && c.Status == "LISTEN":
			protocol = "tcp"
		case c.Type == 2 && c.Raddr.IP == "" && c.Laddr.Port != 0:
			protocol = "udp"
		default:
			continue
		}
		key := protocol + c.Laddr.IP + ":" + itoa(int(c.Laddr.Port))
		if seen[key] {
			continue
		}
		seen[key] = true
		p := proto.ListenPort{Protocol: protocol, Address: c.Laddr.IP, Port: c.Laddr.Port}
		if c.Pid > 0 {
			if n, ok := names[c.Pid]; ok {
				p.Process = n
			} else if proc, err := process.NewProcessWithContext(ctx, c.Pid); err == nil {
				if n, err := proc.NameWithContext(ctx); err == nil {
					names[c.Pid], p.Process = n, n
				}
			}
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Protocol < out[j].Protocol
	})
	return out
}

func itoa(i int) string {
	var b [20]byte
	n := len(b)
	if i == 0 {
		return "0"
	}
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}
