package main

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AlzyWelzy/sentinel/proto"
)

func TestLimiterRefills(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newLimiter(60, 2)
	l.now = func() time.Time { return now }
	for i := range 2 {
		if ok, _ := l.allow("a"); !ok {
			t.Fatalf("request %d refused within the burst", i)
		}
	}
	ok, wait := l.allow("a")
	if ok || wait <= 0 || wait > time.Second {
		t.Fatalf("over the burst: ok=%v wait=%v", ok, wait)
	}
	if ok, _ := l.allow("b"); !ok {
		t.Fatal("another key shares the bucket")
	}
	now = now.Add(time.Second)
	if ok, _ := l.allow("a"); !ok {
		t.Fatal("not refilled after a second at 1/s")
	}
}

func TestLimitedAnswers429WithRetryAfter(t *testing.T) {
	s := &server{limits: map[string]*limiter{"metrics": newLimiter(1, 1)}}
	h := s.limited("metrics", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	codes := []int{}
	for range 2 {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/metrics", nil)
		req.Header.Set("Authorization", "Bearer pgh_x")
		h(rec, req)
		codes = append(codes, rec.Code)
		if rec.Code == http.StatusTooManyRequests && rec.Header().Get("Retry-After") == "" {
			t.Fatal("429 without Retry-After")
		}
	}
	if codes[0] != http.StatusOK || codes[1] != http.StatusTooManyRequests {
		t.Fatalf("codes = %v", codes)
	}
}

// A body over the limit is 413 (agents split and retry), never 400 (they drop).
func TestOversizedBodyIs413(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(`{"batches":[{"ts":1,"samples":[{"name":"` + strings.Repeat("a", maxBodyBytes) + `"}]}]}`))
	gz.Close()
	req := httptest.NewRequest(http.MethodPost, "/v1/metrics", &buf)
	req.Header.Set("Content-Encoding", "gzip")
	var v proto.MetricsRequest
	rec := httptest.NewRecorder()
	bodyError(rec, decodeBody(req, &v))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("code = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	bodyError(rec, decodeBody(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{")), &v))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON code = %d", rec.Code)
	}
}

func TestBatchesOutsideTheClockWindowAreDropped(t *testing.T) {
	now := time.Now()
	sample := []proto.Sample{{Name: "sentinel_cpu_usage_percent", Value: 1}}
	req := proto.MetricsRequest{Batches: []proto.Batch{
		{TimestampMs: now.UnixMilli(), Samples: sample},
		{TimestampMs: now.Add(-24 * time.Hour).UnixMilli(), Samples: sample},
		{TimestampMs: now.Add(time.Hour).UnixMilli(), Samples: sample},
		{TimestampMs: now.Add(-48 * time.Hour).UnixMilli(), Samples: sample},
	}}
	_, kept, dropped := toPrometheusText(req, hostIdentity{HostID: "h", TenantID: "t"}, &hostConfig{checks: map[string]checkDef{}}, now)
	if kept != 2 || dropped != 2 {
		t.Fatalf("kept=%d dropped=%d", kept, dropped)
	}
}
