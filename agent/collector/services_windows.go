//go:build windows

package collector

import (
	"context"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/AlzyWelzy/sentinel/proto"
)

// serviceSamples asks the Service Control Manager for each watched service by
// its service name (W3SVC, MSSQLSERVER), case-insensitively. A service that
// doesn't exist reports as not running.
func serviceSamples(_ context.Context, names []string) []proto.Sample {
	if len(names) == 0 {
		return nil
	}
	m, err := mgr.Connect()
	if err != nil {
		return nil
	}
	defer m.Disconnect()
	var out []proto.Sample
	for _, n := range names {
		if !validServiceName(n) {
			continue
		}
		out = append(out, sample("sentinel_service_up", boolValue(running(m, n)), "service", n))
	}
	return out
}

func running(m *mgr.Mgr, name string) bool {
	s, err := m.OpenService(name)
	if err != nil {
		return false
	}
	defer s.Close()
	st, err := s.Query()
	return err == nil && st.State == svc.Running
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
