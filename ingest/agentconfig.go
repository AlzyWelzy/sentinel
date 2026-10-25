package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/example-org/pulsegrid/proto"
)

// configTTL bounds how stale a host's config can be: a new alert rule or
// check reaches the agent within this plus one push (the push response
// carries the version, and the agent refetches when it changes).
const configTTL = 10 * time.Second

// hostConfig is a host's computed config plus what ingest needs to accept
// its check results: which check ids it runs, and whose they are.
type hostConfig struct {
	cfg      proto.AgentConfig
	checks   map[string]checkDef
	region   string
	loadedAt time.Time
}

type configCache struct {
	mu      sync.Mutex
	entries map[string]*hostConfig
}

func newConfigCache() *configCache { return &configCache{entries: map[string]*hostConfig{}} }

func (c *configCache) get(hostID string) (*hostConfig, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[hostID]
	if !ok || time.Since(e.loadedAt) > configTTL {
		return nil, false
	}
	return e, true
}

func (c *configCache) put(hostID string, e *hostConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[hostID] = e
	// Drop expired entries now and then so removed hosts don't pile up.
	if len(c.entries)%256 == 0 {
		for k, v := range c.entries {
			if time.Since(v.loadedAt) > configTTL {
				delete(c.entries, k)
			}
		}
	}
}

func (c *configCache) forget(hostID string) {
	c.mu.Lock()
	delete(c.entries, hostID)
	c.mu.Unlock()
}

// configVersion fingerprints a config, so the agent can tell when to refetch.
func configVersion(cfg proto.AgentConfig) string {
	cfg.Version = ""
	b, _ := json.Marshal(cfg)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// loadHostConfig builds the host's config from the database. On an error
// the zero entry is returned with the error, so the caller can decide
// whether to serve partial config (registration) or fail (config fetch).
func (s *server) loadHostConfig(ctx context.Context, id hostIdentity) (*hostConfig, error) {
	if e, ok := s.configs.get(id.HostID); ok {
		return e, nil
	}
	cfg := proto.AgentConfig{
		IngestURL:       s.cfg.PublicIngestURL,
		IntervalSeconds: s.cfg.IntervalSeconds,
		LatestVersion:   s.agentVersionFor(ctx, id),
		DownloadURL:     s.cfg.DownloadURL,
	}
	e := &hostConfig{checks: map[string]checkDef{}}
	var err error
	if cfg.WatchProcesses, cfg.WatchServices, err = s.store.watches(ctx, id); err != nil {
		e.cfg = cfg
		return e, err
	}
	checks, region, err := s.store.hostChecks(ctx, id)
	if err != nil {
		e.cfg = cfg
		return e, err
	}
	for _, c := range checks {
		cfg.Checks = append(cfg.Checks, c.Check)
		e.checks[c.ID] = c
	}
	if cfg.Actions, err = s.store.pendingActions(ctx, id.HostID); err != nil {
		e.cfg = cfg
		return e, err
	}
	cfg.Version = configVersion(cfg)
	e.cfg, e.region, e.loadedAt = cfg, region, time.Now()
	s.configs.put(id.HostID, e)
	return e, nil
}
