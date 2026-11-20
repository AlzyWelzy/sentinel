//go:build !windows

package collector

import (
	"context"

	"github.com/AlzyWelzy/sentinel/proto"
)

func windowsPackages(context.Context) []proto.Package { return nil }
