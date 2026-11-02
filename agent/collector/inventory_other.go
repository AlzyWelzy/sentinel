//go:build !windows

package collector

import (
	"context"

	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

func windowsPackages(context.Context) []proto.Package { return nil }
