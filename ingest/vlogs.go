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
	"sync"
	"time"
	"unicode/utf8"

	"github.com/AlzyWelzy/sentinel/proto"
)

const (
	maxLogEntriesPerReq = 5000
	maxLogLine          = 8192
	maxLogSource        = 200
)

var logLevels = map[string]bool{"": true, "error": true, "warning": true, "info": true, "debug": true}

// vlogs stores log lines in VictoriaLogs. Each Sentinel tenant writes to
// its own VictoriaLogs account (the AccountID header, tenants.logs_account_id),
// so a query can only ever see its own account's lines.
type vlogs struct {
	baseURL  string
	client   *http.Client
	accounts sync.Map // tenant id → account id; assigned once, never changes
}

// logRow is one JSON line for /insert/jsonline. host_id, source and level
// form the stream; host_id comes from the host token, never from the agent.
type logRow struct {
	Time   string `json:"_time"`
	Msg    string `json:"_msg"`
	HostID string `json:"host_id"`
	Source string `json:"source"`
	Level  string `json:"level"`
}

// toLogRows validates and normalises entries, in time order. Timestamps out
// of a sane window are replaced with now.
func toLogRows(entries []proto.LogEntry, hostID string, now time.Time) ([]logRow, int) {
	rows := make([]logRow, 0, len(entries))
	stamps := make([]int64, 0, len(entries))
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
		level := e.Level
		if level == "" {
			level = "unknown"
		}
		rows = append(rows, logRow{
			Time:   time.Unix(0, ts).UTC().Format(time.RFC3339Nano),
			Msg:    line,
			HostID: hostID,
			Source: source,
			Level:  level,
		})
		stamps = append(stamps, ts)
	}
	idx := make([]int, len(rows))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return stamps[idx[a]] < stamps[idx[b]] })
	out := make([]logRow, len(rows))
	for i, j := range idx {
		out[i] = rows[j]
	}
	return out, dropped
}

func (v *vlogs) push(ctx context.Context, account int64, rows []logRow) error {
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	u := strings.TrimRight(v.baseURL, "/") +
		"/insert/jsonline?_stream_fields=host_id,source,level&_msg_field=_msg&_time_field=_time"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/stream+json")
	req.Header.Set("AccountID", strconv.FormatInt(account, 10))
	req.Header.Set("ProjectID", "0")
	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("victorialogs: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// account is the tenant's VictoriaLogs AccountID, cached for the process.
func (s *server) logsAccount(ctx context.Context, tenantID string) (int64, error) {
	if v, ok := s.vlogs.accounts.Load(tenantID); ok {
		return v.(int64), nil
	}
	id, err := s.store.logsAccount(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	s.vlogs.accounts.Store(tenantID, id)
	return id, nil
}

func (s *server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if s.vlogs == nil {
		httpError(w, http.StatusNotFound, "log search isn't enabled")
		return
	}
	id, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	var req proto.LogsRequest
	if err := decodeBody(r, &req); err != nil {
		bodyError(w, err)
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
	rows, invalid := toLogRows(req.Entries[:allowed], id.HostID, time.Now())
	if len(rows) > 0 {
		account, err := s.logsAccount(r.Context(), id.TenantID)
		if err == nil {
			err = s.vlogs.push(r.Context(), account, rows)
		}
		if err != nil {
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
