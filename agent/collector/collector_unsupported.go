//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !windows

package collector

import (
	"context"
	"errors"
	"runtime"

	"github.com/AlzyWelzy/sentinel/proto"
)

var errUnsupported = errors.New("sentinel agent doesn't support " + runtime.GOOS + " yet")

func New() (Collector, error) { return nil, errUnsupported }

func Info(context.Context) (HostInfo, error) { return HostInfo{}, errUnsupported }

func Meta(context.Context) proto.HostMeta { return proto.HostMeta{} }
