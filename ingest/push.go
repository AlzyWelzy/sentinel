package main

// Push checks: a cron job, a backup script or an app calls
// /push/<token>?status=up&msg=…&ping=… (GET or POST) and the alerter opens
// an incident when the calls stop or one says down. The token is the only
// credential, so unknown tokens get the same 404 as a bad path, and each
// token has its own rate limit.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	pushTokenMin = 20
	pushTokenMax = 64
)

func pushTokenOK(t string) bool {
	if len(t) < pushTokenMin || len(t) > pushTokenMax {
		return false
	}
	for _, c := range t {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (s *server) handlePush(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !pushTokenOK(token) {
		httpError(w, http.StatusNotFound, "unknown push URL")
		return
	}
	if l := s.limits["push"]; l != nil {
		if ok, wait := l.allow(hashSecret(token)); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
			httpError(w, http.StatusTooManyRequests, "too many pushes, slow down")
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		httpError(w, http.StatusBadRequest, "unreadable form")
		return
	}
	status := strings.ToLower(orDefault(r.Form.Get("status"), "up"))
	if status != "up" && status != "down" {
		httpError(w, http.StatusBadRequest, "status is up or down")
		return
	}
	var ping float64
	if p := r.Form.Get("ping"); p != "" {
		v, err := strconv.ParseFloat(p, 64)
		if err != nil || v < 0 || v > 86_400_000 {
			httpError(w, http.StatusBadRequest, "ping is a duration in milliseconds")
			return
		}
		ping = v
	}
	msg := cleanField(r.Form.Get("msg"), 300)
	if msg == "" {
		msg = "push received"
		if status == "down" {
			msg = "push reported down"
		}
	}

	var checkID, tenantID string
	err := s.store.pool.QueryRow(r.Context(), `
		SELECT c.id, c.tenant_id FROM checks c JOIN tenants t ON t.id = c.tenant_id AND t.status = 'active'
		 WHERE c.push_token = $1 AND c.type = 'push' AND c.enabled`, token).Scan(&checkID, &tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		httpError(w, http.StatusNotFound, "unknown push URL")
		return
	}
	if err != nil {
		s.log.Error("push lookup", "err", err)
		httpError(w, http.StatusServiceUnavailable, "try again shortly")
		return
	}
	now := time.Now()
	ok := status == "up"
	res := storedCheckResult{OK: ok, Detail: msg, LatencyMs: ping, Ts: now.UnixMilli()}
	b, _ := json.Marshal(res)
	pipe := s.cache.rdb.Pipeline()
	pipe.HSet(r.Context(), checkResultKey+checkID, checkID, b)
	if !ok {
		pipe.HSet(r.Context(), checkResultKey+checkID, lastFailurePrefix+checkID, b)
	}
	pipe.Expire(r.Context(), checkResultKey+checkID, checkResultTTL)
	if _, err := pipe.Exec(r.Context()); err != nil {
		s.log.Error("push store", "err", err, "check_id", checkID)
		httpError(w, http.StatusServiceUnavailable, "try again shortly")
		return
	}
	up := 0
	if ok {
		up = 1
	}
	id := escapeLabelValue(checkID)
	body := fmt.Sprintf("sentinel_check_up{check_id=\"%s\"} %d %d\n", id, up, now.UnixMilli())
	if ping > 0 {
		body += fmt.Sprintf("sentinel_check_latency_seconds{check_id=\"%s\"} %g %d\n", id, ping/1000, now.UnixMilli())
	}
	if err := s.vm.write(r.Context(), tenantID, []byte(body)); err != nil {
		// The result is stored and alerting reads it from Redis; only the
		// uptime history misses this point.
		s.log.Warn("push sample not written", "err", err, "check_id", checkID)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
