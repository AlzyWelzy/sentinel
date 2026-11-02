package plugins

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

// collectScript runs a local program and reads Prometheus text (or plain
// "name value" lines, which is the same thing without labels) from its
// output. It runs as the agent's unprivileged user.
//
//	type = script
//	command = /etc/sentinel/scripts/queue-depth.sh
//
// The program must be owned by root and not writable by others, like the
// plugin file itself.
func collectScript(ctx context.Context, c Config) ([]proto.Sample, error) {
	command := setting(c, "command", "")
	if command == "" {
		return nil, fmt.Errorf("command is required")
	}
	args := strings.Fields(command)
	if !filepath.IsAbs(args[0]) {
		return nil, fmt.Errorf("command must be an absolute path")
	}
	if err := CheckOwnership(args[0]); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedBuffer{buf: &stdout, max: 4 << 20}
	cmd.Stderr = &limitedBuffer{buf: &stderr, max: 4 << 10}
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return ParseExposition(stdout.String(), nil, maxCustomSeries)
}

type limitedBuffer struct {
	buf *bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		if len(p) > room {
			l.buf.Write(p[:room])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil
}
