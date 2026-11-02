//go:build !linux

package checks

import (
	"context"
	"net/netip"

	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

func tracePath(_ context.Context, _ netip.Addr, _ int) ([]proto.Hop, string) {
	return nil, "path tracing runs on Linux agents only"
}
