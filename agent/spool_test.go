package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AlzyWelzy/pulsegrid-beyond/agent/checks"
	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

func TestSpoolKeepsBatchesWithTheSameTimestamp(t *testing.T) {
	sp, err := newSpool(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := sp.add(proto.Batch{TimestampMs: 42}); err != nil {
			t.Fatal(err)
		}
	}
	batches, _, _ := sp.oldest(10)
	if len(batches) != 3 {
		t.Fatalf("got %d batches, want 3", len(batches))
	}
}

func TestSpoolDropsInterruptedWrites(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "spool"), 0o700); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, "spool", "00000000000000000001-aa.json.tmp")
	os.WriteFile(tmp, []byte(`{"ts":1,"sam`), 0o600)
	sp, err := newSpool(dir, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("leftover temp file kept")
	}
	if b, _, _ := sp.oldest(10); len(b) != 0 {
		t.Fatalf("temp file read as a batch: %v", b)
	}
}

// Ingest answering 413 makes the agent send fewer batches per push instead
// of dropping them; every batch still arrives.
func TestFlushSplitsOnTooLarge(t *testing.T) {
	received := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gz, _ := gzip.NewReader(r.Body)
		body, _ := io.ReadAll(gz)
		var req proto.MetricsRequest
		json.Unmarshal(body, &req)
		if len(req.Batches) > 3 {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			return
		}
		received += len(req.Batches)
		json.NewEncoder(w).Encode(proto.MetricsResponse{Accepted: len(req.Batches)})
	}))
	defer srv.Close()

	sp, _ := newSpool(t.TempDir(), 100)
	for i := range 20 {
		sp.add(proto.Batch{TimestampMs: int64(i + 1), Samples: []proto.Sample{{Name: "x", Value: 1}}})
	}
	a := &agent{
		st:     state{IngestURL: srv.URL, HostToken: "pgh_test"},
		spool:  sp,
		client: newClient(),
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		checks: checks.NewRunner("test"),
		meta:   &proto.HostMeta{}, metaAt: time.Now(),
		refreshNow: make(chan struct{}, 1),
	}
	a.flush(context.Background())
	if received != 20 {
		t.Fatalf("ingest received %d of 20 batches", received)
	}
	if left, _, _ := sp.oldest(100); len(left) != 0 {
		t.Fatalf("%d batches left in the spool", len(left))
	}
}

// A removed server (or a suspended organisation) gets 401 from ingest. The
// agent keeps its data but stops re-sending it every tick, and resumes as
// soon as a push is accepted again.
func TestFlushBacksOffWhenTokenRefused(t *testing.T) {
	var calls int
	status := http.StatusUnauthorized
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if status != http.StatusOK {
			http.Error(w, "invalid host token", status)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`{"accepted":1}`))
	}))
	defer srv.Close()

	sp, err := newSpool(t.TempDir(), 100)
	if err != nil {
		t.Fatal(err)
	}
	sp.add(proto.Batch{TimestampMs: 1, Samples: []proto.Sample{{Name: "x", Value: 1}}})
	a := &agent{
		st:     state{IngestURL: srv.URL, HostToken: "pgh_test"},
		spool:  sp,
		client: newClient(),
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		checks: checks.NewRunner("test"),
		meta:   &proto.HostMeta{}, metaAt: time.Now(),
		refreshNow: make(chan struct{}, 1),
	}
	a.flush(context.Background())
	a.flush(context.Background())
	a.flush(context.Background())
	if calls != 1 {
		t.Fatalf("refused pushes were retried at once: %d requests", calls)
	}
	if b, _, _ := sp.oldest(10); len(b) != 1 {
		t.Fatalf("refused data was dropped: %d batches left", len(b))
	}
	if got := time.Until(a.retryAt); got < 50*time.Second || got > time.Minute {
		t.Fatalf("first backoff %v, want about a minute", got)
	}

	status = http.StatusOK
	a.retryAt = time.Now().Add(-time.Second)
	a.flush(context.Background())
	if b, _, _ := sp.oldest(10); len(b) != 0 || a.refusedPushes != 0 {
		t.Fatalf("after recovery: %d batches left, %d refusals counted", len(b), a.refusedPushes)
	}
}

func TestRefusedBackoffGrowsToHalfAnHour(t *testing.T) {
	for n, want := range map[int]time.Duration{1: time.Minute, 2: 2 * time.Minute, 5: 16 * time.Minute, 6: 30 * time.Minute, 50: 30 * time.Minute} {
		if got := refusedBackoff(n); got != want {
			t.Errorf("refusedBackoff(%d) = %v, want %v", n, got, want)
		}
	}
}

// One NaN from a plugin (an empty Prometheus summary) mustn't lose the
// batch: the finite samples are kept.
func TestSpoolKeepsBatchesWithNaN(t *testing.T) {
	sp, err := newSpool(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	err = sp.add(proto.Batch{TimestampMs: 1, Samples: []proto.Sample{
		{Name: "ok", Value: 1}, {Name: "nan", Value: math.NaN()}, {Name: "inf", Value: math.Inf(1)},
	}})
	if err != nil {
		t.Fatalf("batch with NaN refused: %v", err)
	}
	b, _, _ := sp.oldest(1)
	if len(b) != 1 || len(b[0].Samples) != 1 || b[0].Samples[0].Name != "ok" {
		t.Fatalf("got %+v", b)
	}
}
