//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !windows

package collector

import (
	"context"
	"errors"
	"runtime"
)

var errUnsupported = errors.New("pulsegrid agent doesn't support " + runtime.GOOS + " yet")

func New() (Collector, error) { return nil, errUnsupported }

func Info(context.Context) (HostInfo, error) { return HostInfo{}, errUnsupported }
