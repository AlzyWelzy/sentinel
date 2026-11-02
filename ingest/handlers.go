package main

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

const (
	hostTokenPrefix = "pgh_"
	// After decompression. Agents send at most 20 batches per push, far
	// below this; agents before 0.9.0 drop batches on 413, so the limit
	// stays well above anything they send.
	maxBodyBytes     = 32 << 20
	maxSamplesPerReq = 100_000
)

var errBodyTooLarge = errors.New("body too large")

type server struct {
	cfg     config
	store   *store
	cache   *cache
	vm      *victoriaMetrics
	vlogs   *vlogs // nil when log search is off
	tempo   *tempo // nil when APM is off
	log     *slog.Logger
	configs *configCache
	rollout rolloutCache
	limits  map[string]*limiter
}

// Requests per minute and burst, per host token (per client address for
// registration). An agent catching up after an outage pushes back to back:
// a full 24h spool is 144 pushes, so the burst covers that.
var rateLimits = map[string][2]int{
	"register": {30, 60},
	"metrics":  {60, 200},
	"config":   {20, 30},
	"logs":     {60, 200},
	"traces":   {120, 300},
}

func newLimits() map[string]*limiter {
	m := map[string]*limiter{}
	for name, l := range rateLimits {
		m[name] = newLimiter(l[0], l[1])
	}
	return m
}

// limited refuses a caller over its rate with 429 and Retry-After. Agents
// keep their data and retry on 429, so this only slows them down.
func (s *server) limited(name string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Authorization")
		if key == "" {
			key = publicClientIP(r)
			if key == "" {
				key = r.RemoteAddr
			}
		} else {
			key = hashSecret(key)
		}
		if l := s.limits[name]; l != nil {
			if ok, wait := l.allow(key); !ok {
				w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
				httpError(w, http.StatusTooManyRequests, "too many requests, slow down")
				return
			}
		}
		h(w, r)
	}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/register", s.limited("register", s.handleRegister))
	mux.HandleFunc("POST /v1/metrics", s.limited("metrics", s.handleMetrics))
	mux.HandleFunc("GET /v1/agent/config", s.limited("config", s.handleAgentConfig))
	mux.HandleFunc("POST /v1/logs", s.limited("logs", s.handleLogs))
	mux.HandleFunc("POST /v1/traces", s.limited("traces", s.handleTraces))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})
	return mux
}

// agentConfig is the host's config: endpoints and interval for everyone,
// the processes and services its alert rules watch, its checks and pending
// actions. If those can't be read the agent keeps what it has (an empty
// list here would clear them).
func (s *server) agentConfig(ctx context.Context, id hostIdentity) (proto.AgentConfig, error) {
	e, err := s.loadHostConfig(ctx, id)
	return e.cfg, err
}

func (s *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req proto.RegisterRequest
	if err := decodeBody(r, &req); err != nil {
		bodyError(w, err)
		return
	}
	if req.InstallKey == "" || req.MachineID == "" || req.Hostname == "" {
		httpError(w, http.StatusBadRequest, "install_key, machine_id and hostname are required")
		return
	}
	// Whatever the agent reports is shown in the dashboard and in emails, and
	// Postgres can't store NUL: drop control characters and cap lengths.
	if req.Hostname = cleanHostname(req.Hostname); req.Hostname == "" {
		httpError(w, http.StatusBadRequest, "hostname must be 1 to 253 characters with no control characters")
		return
	}
	if req.MachineID = cleanField(req.MachineID, 200); req.MachineID == "" {
		httpError(w, http.StatusBadRequest, "machine_id is required")
		return
	}
	req.OS = cleanField(req.OS, 50)
	req.Platform = cleanField(req.Platform, 100)
	req.PlatformVersion = cleanField(req.PlatformVersion, 100)
	req.Arch = cleanField(req.Arch, 50)
	req.AgentVersion = cleanField(req.AgentVersion, 50)

	token := hostTokenPrefix + randomToken()
	tokenHash := hashSecret(token)
	id, oldTokenHash, err := s.store.register(r.Context(), hashSecret(req.InstallKey), tokenHash, req)
	switch {
	case errors.Is(err, errUnknownCredential):
		httpError(w, http.StatusUnauthorized, "invalid or revoked install key")
		return
	case errors.Is(err, errTenantSuspended):
		httpError(w, http.StatusForbidden, "monitoring is suspended for this account")
		return
	case err != nil:
		s.log.Error("register failed", "err", err)
		httpError(w, http.StatusInternalServerError, "registration failed")
		return
	}
	if oldTokenHash != "" {
		s.cache.forgetHost(r.Context(), oldTokenHash)
	}
	s.log.Info("host registered", "host_id", id.HostID, "tenant_id", id.TenantID, "hostname", req.Hostname)
	cfg, err := s.agentConfig(r.Context(), id)
	if err != nil {
		// Registered either way; the agent picks the watches up on its next refresh.
		s.log.Warn("watches not loaded", "err", err, "host_id", id.HostID)
	}
	writeJSON(w, http.StatusOK, proto.RegisterResponse{
		HostID: id.HostID, HostToken: token, Config: cfg,
	})
}

func (s *server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	var req proto.MetricsRequest
	if err := decodeBody(r, &req); err != nil {
		bodyError(w, err)
		return
	}
	total := 0
	for _, b := range req.Batches {
		total += len(b.Samples)
	}
	if total > maxSamplesPerReq {
		httpError(w, http.StatusRequestEntityTooLarge, "too many samples in one request")
		return
	}

	hc, err := s.loadHostConfig(r.Context(), id)
	if err != nil {
		// Without the check list, check samples can't be attributed; the
		// rest still go in.
		s.log.Warn("host config not loaded", "err", err, "host_id", id.HostID)
	}
	bodies, kept, dropped := toPrometheusText(req, id, hc, time.Now())
	for tenantID, body := range bodies {
		if err := s.vm.write(r.Context(), tenantID, body); err != nil {
			s.log.Error("metrics write failed", "err", err, "host_id", id.HostID)
			// 503 tells the agent to keep the batch and retry later.
			httpError(w, http.StatusServiceUnavailable, "metrics store unavailable")
			return
		}
	}
	if dropped > 0 {
		s.log.Warn("dropped invalid samples", "host_id", id.HostID, "dropped", dropped)
	}
	if len(req.CheckResults) > 0 {
		if err := s.cache.storeCheckResults(r.Context(), id, hc, req.CheckResults); err != nil {
			s.log.Warn("check results not stored", "err", err, "host_id", id.HostID)
		}
	}
	if len(req.ActionResults) > 0 {
		if err := s.store.finishActions(r.Context(), id.HostID, req.ActionResults); err != nil {
			s.log.Warn("action results not stored", "err", err, "host_id", id.HostID)
		} else {
			s.configs.forget(id.HostID)
		}
	}
	if req.Inventory != nil {
		if err := s.store.saveInventory(r.Context(), id, req.Inventory); err != nil {
			s.log.Warn("inventory not stored", "err", err, "host_id", id.HostID)
		}
	}

	now := time.Now()
	if err := s.cache.markSeen(r.Context(), id.HostID, now); err != nil {
		s.log.Warn("heartbeat not recorded", "err", err, "host_id", id.HostID)
	}
	if err := s.store.touchHost(r.Context(), id.HostID, req.AgentVersion, publicClientIP(r), req.Host); err != nil {
		s.log.Warn("last_seen_at not updated", "err", err, "host_id", id.HostID)
	}
	writeJSON(w, http.StatusOK, proto.MetricsResponse{Accepted: kept, Dropped: dropped, ConfigVersion: hc.cfg.Version})
}

func (s *server) handleAgentConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	cfg, err := s.agentConfig(r.Context(), id)
	if err != nil {
		s.log.Error("loading watches failed", "err", err, "host_id", id.HostID)
		httpError(w, http.StatusServiceUnavailable, "try again later")
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

// authenticate resolves the host token to a host and tenant. This lookup is
// the only source of tenant_id for everything the request writes.
func (s *server) authenticate(w http.ResponseWriter, r *http.Request) (hostIdentity, bool) {
	token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found || !strings.HasPrefix(token, hostTokenPrefix) {
		httpError(w, http.StatusUnauthorized, "missing host token")
		return hostIdentity{}, false
	}
	tokenHash := hashSecret(token)

	id, cached := s.cache.cachedHost(r.Context(), tokenHash)
	if !cached {
		var err error
		id, err = s.store.lookupHost(r.Context(), tokenHash)
		if errors.Is(err, errUnknownCredential) {
			httpError(w, http.StatusUnauthorized, "invalid or revoked host token")
			return hostIdentity{}, false
		}
		if err != nil {
			s.log.Error("host lookup failed", "err", err)
			httpError(w, http.StatusServiceUnavailable, "try again later")
			return hostIdentity{}, false
		}
		s.cache.storeHost(r.Context(), tokenHash, id)
	}
	if !id.Active {
		httpError(w, http.StatusForbidden, "monitoring is suspended for this account")
		return hostIdentity{}, false
	}
	return id, true
}

// readBody returns the request body, inflated if gzipped, up to maxBodyBytes.
func readBody(r *http.Request) ([]byte, error) {
	var reader io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			return nil, errors.New("invalid gzip body")
		}
		defer gz.Close()
		reader = gz
	}
	body, err := io.ReadAll(io.LimitReader(reader, maxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBodyBytes {
		return nil, errBodyTooLarge
	}
	return body, nil
}

// decodeBody reads the whole body first, so a body over the limit is
// reported as too large (413, which agents split and retry) rather than
// as truncated JSON (400, which they drop).
func decodeBody(r *http.Request, v any) error {
	body, err := readBody(r)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return errors.New("invalid JSON body")
	}
	return nil
}

func bodyError(w http.ResponseWriter, err error) {
	if errors.Is(err, errBodyTooLarge) {
		httpError(w, http.StatusRequestEntityTooLarge, err.Error())
		return
	}
	httpError(w, http.StatusBadRequest, err.Error())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"detail": msg})
}

func randomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashSecret matches api/app/services/secrets.py: sha256, hex.
func hashSecret(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}
