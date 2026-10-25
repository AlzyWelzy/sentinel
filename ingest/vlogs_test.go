package main

import (
	"strings"
	"testing"
	"time"

	"github.com/example-org/pulsegrid/proto"
)

func TestToLogRows(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	ns := now.UnixNano()
	rows, dropped := toLogRows([]proto.LogEntry{
		{TimestampNs: ns - 2, Source: "/var/log/app.log", Level: "error", Line: "db down"},
		{TimestampNs: ns - 3, Source: "/var/log/app.log", Level: "error", Line: "earlier"},
		{TimestampNs: ns, Source: "/var/log/app.log", Level: "", Line: "plain"},
		{TimestampNs: 1, Source: "journal/nginx.service", Level: "info", Line: "ancient timestamp"},
		{TimestampNs: ns, Source: "x", Level: "shouting", Line: "bad level"},
		{TimestampNs: ns, Source: "x", Level: "info", Line: "   "},
		{TimestampNs: ns, Source: "", Level: "info", Line: strings.Repeat("a", maxLogLine+10)},
	}, "host-1", now)
	if dropped != 2 || len(rows) != 5 {
		t.Fatalf("dropped=%d rows=%+v", dropped, rows)
	}
	if rows[0].Msg != "earlier" || rows[1].Msg != "db down" {
		t.Fatalf("rows must be in time order: %+v", rows[:2])
	}
	for _, r := range rows {
		if r.HostID != "host-1" {
			t.Fatalf("host_id must come from the token: %+v", r)
		}
		switch r.Msg {
		case "plain":
			if r.Level != "unknown" {
				t.Fatalf("empty level is unknown: %+v", r)
			}
		case "ancient timestamp":
			if r.Time != now.UTC().Format(time.RFC3339Nano) {
				t.Fatalf("out-of-window timestamp must be replaced: %s", r.Time)
			}
		}
		if strings.HasPrefix(r.Msg, "aaa") && (len(r.Msg) != maxLogLine || r.Source != "unknown") {
			t.Fatal("long lines are cut and an empty source is unknown")
		}
	}
}
