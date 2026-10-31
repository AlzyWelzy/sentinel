package logs

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/example-org/pulsegrid/proto"
)

// DockerSocket is where the Docker API listens.
var DockerSocket = "/var/run/docker.sock"

func dockerClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", DockerSocket)
		}},
	}
}

// readDocker ships what running containers printed since last time, as
// source docker:<name>. since maps container ID to the last line's time
// (unix ns); a container seen for the first time starts now (no backfill).
func readDocker(since map[string]int64, max int, now time.Time) ([]proto.LogEntry, map[string]int64, error) {
	hc := dockerClient()
	resp, err := hc.Get("http://docker/containers/json")
	if err != nil {
		return nil, since, err
	}
	var list []struct {
		ID    string   `json:"Id"`
		Names []string `json:"Names"`
	}
	err = json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if err != nil {
		return nil, since, fmt.Errorf("docker: %w", err)
	}
	next := map[string]int64{}
	var out []proto.LogEntry
	for _, c := range list {
		last, known := since[c.ID]
		if !known {
			next[c.ID] = now.UnixNano()
			continue
		}
		next[c.ID] = last
		if len(out) >= max {
			continue
		}
		name := c.ID[:12]
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		q := url.Values{"stdout": {"1"}, "stderr": {"1"}, "timestamps": {"1"},
			"since": {strconv.FormatInt(last/1e9, 10)}}
		resp, err := hc.Get("http://docker/containers/" + c.ID + "/logs?" + q.Encode())
		if err != nil {
			continue
		}
		entries, newest := parseDockerLogs(io.LimitReader(resp.Body, maxReadBytes), "docker:"+name, last, max-len(out))
		resp.Body.Close()
		next[c.ID] = newest
		out = append(out, entries...)
	}
	return out, next, nil
}

// parseDockerLogs reads Docker's log stream: 8-byte frame headers when the
// container has no TTY, plain lines when it has one. Each line starts with
// an RFC 3339 timestamp; lines at or before `after` were already shipped.
func parseDockerLogs(r io.Reader, source string, after int64, max int) ([]proto.LogEntry, int64) {
	br := bufio.NewReaderSize(r, 64<<10)
	var lines []string
	if h, err := br.Peek(8); err == nil && h[0] <= 2 && h[1] == 0 && h[2] == 0 && h[3] == 0 {
		hdr := make([]byte, 8)
		for {
			if _, err := io.ReadFull(br, hdr); err != nil {
				break
			}
			body := make([]byte, binary.BigEndian.Uint32(hdr[4:]))
			if _, err := io.ReadFull(br, body); err != nil {
				break
			}
			lines = append(lines, strings.Split(strings.TrimRight(string(body), "\n"), "\n")...)
		}
	} else {
		sc := bufio.NewScanner(br)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}
	}
	newest := after
	var out []proto.LogEntry
	for _, l := range lines {
		ts, text, ok := strings.Cut(l, " ")
		t, err := time.Parse(time.RFC3339Nano, ts)
		if !ok || err != nil || t.UnixNano() <= after {
			continue
		}
		if len(out) >= max {
			break
		}
		newest = t.UnixNano()
		text = strings.TrimRight(text, "\r")
		if text != "" {
			out = append(out, proto.LogEntry{TimestampNs: newest, Source: source, Level: DetectLevel(text), Line: clip(text)})
		}
	}
	return out, newest
}
