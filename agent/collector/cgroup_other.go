//go:build !linux

package collector

import "time"

// cgroup limits only exist on Linux.

type cgroupLimits struct {
	cores    float64
	cpuDir   string
	memLimit uint64
	memDir   string
}

func detectLimits(int, uint64) cgroupLimits { return cgroupLimits{} }

func memoryUsed(string) (uint64, bool) { return 0, false }

type cgroupCPU struct{}

func (c *cgroupCPU) percent(cgroupLimits, time.Time) (float64, bool) { return 0, false }
