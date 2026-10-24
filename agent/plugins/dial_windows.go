package plugins

import (
	"context"
	"errors"
	"net"
)

// Named pipes need winio; on Windows point socket at tcp://host:2375 instead.
func dialDocker(context.Context, string) (net.Conn, error) {
	return nil, errors.New(`on Windows set socket = tcp://127.0.0.1:2375 (named pipes aren't supported)`)
}
