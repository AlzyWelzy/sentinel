package main

import (
	"strings"
	"testing"
	"time"

	"github.com/example-org/pulsegrid/proto"
)

func TestToLokiStreams(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	ns := now.UnixNano()
	streams, dropped := toLokiStreams([]proto.LogEntry{
		{TimestampNs: ns - 2, Source: "/var/log/app.log", Level: "error", Line: "db down"},
		{TimestampNs: ns - 3, Source: "/var/log/app.log", Level: "error", Line: "earlier"},
		{TimestampNs: ns, Source: "/var/log/app.log", Level: "", Line: "plain"},
		{TimestampNs: 1, Source: "journal/nginx.service", Level: "info", Line: "ancient timestamp"},
		{TimestampNs: ns, Source: "x", Level: "shouting", Line: "bad level"},
		{TimestampNs: ns, Source: "x", Level: "info", Line: "   "},
		{TimestampNs: ns, Source: "", Level: "info", Line: strings.Repeat("a", maxLogLine+10)},
	}, "host-1", now)
	if dropped != 2 || len(streams) != 4 {
		t.Fatalf("dropped=%d streams=%+v", dropped, streams)
	}
	for _, s := range streams {
		if s.Stream["host_id"] != "host-1" {
			t.Fatalf("host_id must come from the token: %+v", s.Stream)
		}
		switch s.Stream["source"] + "|" + s.Stream["level"] {
		case "/var/log/app.log|error":
			if s.Values[0][1] != "earlier" || s.Values[1][1] != "db down" {
				t.Fatalf("values must be in time order: %+v", s.Values)
			}
		case "/var/log/app.log|unknown":
		case "journal/nginx.service|info":
			if s.Values[0][0] == "1" {
				t.Fatal("out-of-window timestamp must be replaced")
			}
		case "unknown|info":
			if len(s.Values[0][1]) != maxLogLine {
				t.Fatal("long lines must be cut")
			}
		default:
			t.Fatalf("unexpected stream %+v", s.Stream)
		}
	}
}
