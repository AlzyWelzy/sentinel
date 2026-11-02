//go:build linux

package collector

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

const serviceCheckTimeout = 5 * time.Second

// serviceSamples reports whether each watched service is running, and on
// systemd hosts how many units are in the failed state.
func serviceSamples(ctx context.Context, names []string) []proto.Sample {
	ctx, cancel := context.WithTimeout(ctx, serviceCheckTimeout)
	defer cancel()
	systemctl := findBinary("systemctl", "/usr/bin/systemctl", "/bin/systemctl")
	_, err := os.Stat("/run/systemd/system")
	systemd := systemctl != "" && err == nil

	var out []proto.Sample
	if systemd {
		if failed, err := exec.CommandContext(ctx, systemctl, "list-units", "--state=failed",
			"--no-legend", "--plain", "--no-pager").Output(); err == nil {
			out = append(out, sample("pulsegrid_systemd_failed_units", float64(countLines(failed))))
		}
	}
	var valid []string
	for _, n := range names {
		if validServiceName(n) {
			valid = append(valid, n)
		}
	}
	if len(valid) == 0 {
		return out
	}
	if systemd {
		return append(out, systemdServices(ctx, systemctl, valid)...)
	}
	for _, n := range valid {
		out = append(out, sample("pulsegrid_service_up", boolValue(sysvRunning(ctx, n)), "service", n))
	}
	return out
}

// systemdServices asks systemctl about every unit in one call. It prints one
// block per unit, in the order asked, even for units that don't exist.
func systemdServices(ctx context.Context, systemctl string, names []string) []proto.Sample {
	args := []string{"show", "--property=ActiveState", "--no-pager", "--"}
	for _, n := range names {
		args = append(args, unitName(n))
	}
	raw, err := exec.CommandContext(ctx, systemctl, args...).Output()
	if err != nil {
		return nil
	}
	states := parseActiveStates(raw)
	if len(states) != len(names) {
		return nil
	}
	out := make([]proto.Sample, 0, len(names))
	for i, n := range names {
		up := states[i] == "active" || states[i] == "reloading"
		out = append(out, sample("pulsegrid_service_up", boolValue(up), "service", n))
	}
	return out
}

func parseActiveStates(raw []byte) []string {
	var states []string
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "ActiveState="); ok {
			states = append(states, v)
		}
	}
	return states
}

var unitSuffixes = []string{".service", ".socket", ".timer", ".mount", ".target", ".path", ".scope", ".slice"}

// unitName adds ".service" when no unit type is given ("nginx" -> "nginx.service").
func unitName(n string) string {
	for _, s := range unitSuffixes {
		if strings.HasSuffix(n, s) {
			return n
		}
	}
	return n + ".service"
}

// sysvRunning checks a service on OpenRC or SysV init by the exit status of
// its status command.
func sysvRunning(ctx context.Context, name string) bool {
	if rc := findBinary("rc-service", "/sbin/rc-service", "/usr/sbin/rc-service"); rc != "" {
		return exec.CommandContext(ctx, rc, name, "status").Run() == nil
	}
	if svc := findBinary("service", "/usr/sbin/service", "/sbin/service"); svc != "" {
		return exec.CommandContext(ctx, svc, name, "status").Run() == nil
	}
	return false
}

func countLines(b []byte) int {
	n := 0
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(line)) > 0 {
			n++
		}
	}
	return n
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// findBinary looks a tool up in PATH, then at its usual locations: services
// and cron often run with a minimal PATH.
func findBinary(name string, paths ...string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
