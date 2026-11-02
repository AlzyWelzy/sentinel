//go:build darwin

package collector

import (
	"context"

	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

// macOS builds are for development; launchd services aren't checked.
func serviceSamples(context.Context, []string) []proto.Sample { return nil }
