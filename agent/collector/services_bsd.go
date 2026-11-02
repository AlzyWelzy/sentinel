//go:build freebsd || openbsd || netbsd

package collector

import (
	"context"
	"os/exec"
	"runtime"
	"time"

	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

const serviceCheckTimeout = 5 * time.Second

// serviceSamples checks each watched rc.d service by the exit status of its
// status command. "onestatus" works whether or not the service is enabled in
// rc.conf.
func serviceSamples(ctx context.Context, names []string) []proto.Sample {
	var out []proto.Sample
	for _, n := range names {
		if !validServiceName(n) {
			continue
		}
		ctx, cancel := context.WithTimeout(ctx, serviceCheckTimeout)
		up := exec.CommandContext(ctx, statusCommand(n)[0], statusCommand(n)[1:]...).Run() == nil
		cancel()
		out = append(out, sample("sentinel_service_up", boolValue(up), "service", n))
	}
	return out
}

func statusCommand(name string) []string {
	switch runtime.GOOS {
	case "openbsd":
		return []string{"/usr/sbin/rcctl", "check", name}
	case "netbsd":
		return []string{"/etc/rc.d/" + name, "onestatus"}
	default:
		return []string{"/usr/sbin/service", name, "onestatus"}
	}
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
