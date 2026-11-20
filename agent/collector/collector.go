// Package collector gathers host metrics. Each OS gets its own implementation
// behind the same interface, selected at build time by file suffix
// (collector_linux.go, later collector_freebsd.go, collector_windows.go, ...),
// so adding a platform never touches the agent's core.
package collector

import (
	"context"

	"github.com/AlzyWelzy/sentinel/proto"
)

type Collector interface {
	Collect(ctx context.Context) ([]proto.Sample, error)
	// Watch sets the processes and services to report on even when idle or
	// absent (alert rules for "nginx isn't running" need a 0, not silence).
	Watch(processes, services []string)
}

// HostInfo describes the machine at registration time.
type HostInfo struct {
	MachineID       string
	Hostname        string
	OS              string
	Platform        string
	PlatformVersion string
	Arch            string
}

func sample(name string, value float64, labels ...string) proto.Sample {
	s := proto.Sample{Name: name, Value: value}
	if len(labels) > 0 {
		s.Labels = make(map[string]string, len(labels)/2)
		for i := 0; i+1 < len(labels); i += 2 {
			s.Labels[labels[i]] = labels[i+1]
		}
	}
	return s
}
