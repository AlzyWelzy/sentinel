package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/example-org/pulsegrid/proto"
)

const (
	maxLogEntriesPerReq = 5000
	maxLogLine          = 8192
	maxLogSource        = 200
)

var logLevels = map[string]bool{"": true, "error": true, "warning": true, "info": true, "debug": true}

// loki stores log lines, one Loki tenant (X-Scope-OrgID) per Pulsegrid
// tenant, so a query can only ever see its own account's lines.
type loki struct {
	baseURL string
	client  *http.Client
}

type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

// toLokiStreams groups entries by source and level. host_id comes from the
// host token, never from the agent. Timestamps out of a sane window are
// replaced with now, since Loki rejects them.
func toLokiStreams(entries []proto.LogEntry, hostID string, now time.Time) ([]lokiStream, int) {
	type key struct{ source, level string }
	streams := map[key]*lokiStream{}
	dropped := 0
	oldest, newest := now.Add(-6*time.Hour).UnixNano(), now.Add(time.Minute).UnixNano()
	for _, e := range entries {
		if !logLevels[e.Level] || strings.TrimSpace(e.Line) == "" {
			dropped++
			continue
		}
		source := strings.ToValidUTF8(e.Source, "?")
		if source == "" {
			source = "unknown"
		}
		if len(source) > maxLogSource {
			source = source[:maxLogSource]
		}
		line := e.Line
		if !utf8.ValidString(line) {
			line = strings.ToValidUTF8(line, "?")
		}
		if len(line) > maxLogLine {
			line = line[:maxLogLine]
		}
		ts := e.TimestampNs
		if ts < oldest || ts > newest {
			ts = now.UnixNano()
		}
		k := key{source, e.Level}
		s, ok := streams[k]
		if !ok {
			level := e.Level
			if level == "" {
				level = "unknown"
			}
			s = &lokiStream{Stream: map[string]string{"host_id": hostID, "source": source, "level": level}}
			streams[k] = s
		}
		s.Values = append(s.Values, [2]string{strconv.FormatInt(ts, 10), line})
	}
	out := make([]lokiStream, 0, len(streams))
	for _, s := range streams {
		sort.SliceStable(s.Values, func(i, j int) bool { return s.Values[i][0] < s.Values[j][0] })
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Stream["source"]+out[i].Stream["level"] < out[j].Stream["source"]+out[j].Stream["level"]
	})
	return out, dropped
}

func (l *loki) push(ctx context.Context, tenantID string, streams []lokiStream) error {
	body, err := json.Marshal(map[string]any{"streams": streams})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(l.baseURL, "/")+"/loki/api/v1/push", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Scope-OrgID", tenantID)
	resp, err := l.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("loki: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

func (s *server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if s.loki == nil {
		httpError(w, http.StatusNotFound, "log search isn't enabled")
		return
	}
	id, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	var req proto.LogsRequest
	if err := decodeBody(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Entries) > maxLogEntriesPerReq {
		httpError(w, http.StatusRequestEntityTooLarge, "too many log lines in one request")
		return
	}
	// Over the per-host rate the rest of this minute's lines are dropped
	// (and counted), not retried: a runaway log mustn't fill the store.
	allowed, err := s.cache.takeLogQuota(r.Context(), id.HostID, len(req.Entries), s.cfg.LogLinesPerMinute)
	if err != nil {
		s.log.Warn("log quota unavailable", "err", err, "host_id", id.HostID)
		allowed = len(req.Entries)
	}
	overQuota := len(req.Entries) - allowed
	streams, invalid := toLokiStreams(req.Entries[:allowed], id.HostID, time.Now())
	if len(streams) > 0 {
		if err := s.loki.push(r.Context(), id.TenantID, streams); err != nil {
			s.log.Error("log write failed", "err", err, "host_id", id.HostID)
			httpError(w, http.StatusServiceUnavailable, "log store unavailable")
			return
		}
	}
	if overQuota > 0 {
		s.log.Warn("log lines over quota dropped", "host_id", id.HostID, "dropped", overQuota)
	}
	writeJSON(w, http.StatusOK, proto.LogsResponse{Accepted: allowed - invalid, Dropped: overQuota + invalid})
}
