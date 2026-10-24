//go:build !windows

package collector

import (
	"context"

	"github.com/example-org/pulsegrid/proto"
)

func windowsPackages(context.Context) []proto.Package { return nil }
