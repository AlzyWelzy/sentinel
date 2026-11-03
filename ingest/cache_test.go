package main

import (
	"testing"
	"time"

	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

func TestClockAhead(t *testing.T) {
	now := time.Now()
	req := proto.MetricsRequest{Batches: []proto.Batch{
		{TimestampMs: now.Add(-3 * time.Hour).UnixMilli()}, // spool replay: fine
		{TimestampMs: now.Add(15 * time.Minute).UnixMilli()},
	}}
	if got := clockAhead(req, now).Round(time.Minute); got != 15*time.Minute {
		t.Fatalf("clockAhead = %v", got)
	}
	if got := clockAhead(proto.MetricsRequest{Batches: []proto.Batch{{TimestampMs: now.Add(-time.Hour).UnixMilli()}}}, now); got != 0 {
		t.Fatalf("a clock behind counted as ahead: %v", got)
	}
}
