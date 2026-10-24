//go:build !windows

package plugins

import (
	"context"
	"net"
)

func dialDocker(ctx context.Context, sock string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", sock)
}
