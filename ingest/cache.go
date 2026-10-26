package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/example-org/pulsegrid/proto"
)

// Key layout shared with the API (api/app/services/heartbeats.py). Change both together.
const (
	lastSeenKey       = "pg:last_seen:"
	hostTokenCacheKey = "pg:host_token:"

	hostTokenCacheTTL = 5 * time.Minute
	lastSeenTTL       = 7 * 24 * time.Hour
)

type cache struct {
	rdb *redis.Client
}

// cachedHost avoids a Postgres lookup on every push. The API deletes the entry
// when a host is removed or its tenant is suspended, so changes apply at once;
// the TTL only bounds staleness if that delete is ever missed.
func (c *cache) cachedHost(ctx context.Context, tokenHash string) (hostIdentity, bool) {
	v, err := c.rdb.Get(ctx, hostTokenCacheKey+tokenHash).Result()
	if err != nil {
		return hostIdentity{}, false
	}
	parts := strings.Split(v, "|")
	if len(parts) != 3 {
		return hostIdentity{}, false
	}
	return hostIdentity{HostID: parts[0], TenantID: parts[1], Active: parts[2] == "1"}, true
}

func (c *cache) storeHost(ctx context.Context, tokenHash string, id hostIdentity) {
	active := "0"
	if id.Active {
		active = "1"
	}
	c.rdb.Set(ctx, hostTokenCacheKey+tokenHash, id.HostID+"|"+id.TenantID+"|"+active, hostTokenCacheTTL)
}

func (c *cache) forgetHost(ctx context.Context, tokenHash string) {
	c.rdb.Del(ctx, hostTokenCacheKey+tokenHash)
}

func (c *cache) markSeen(ctx context.Context, hostID string, at time.Time) error {
	return c.rdb.Set(ctx, lastSeenKey+hostID, strconv.FormatInt(at.Unix(), 10), lastSeenTTL).Err()
}

// checkResultKey holds the latest result of a check per place it runs: a
// host id, or "probe:<region>". The API and alerter read the detail from it.
const (
	checkResultKey    = "pg:check:"
	checkResultTTL    = 2 * 24 * time.Hour
	lastFailurePrefix = "fail:"
)

type storedCheckResult struct {
	OK        bool             `json:"ok"`
	Detail    string           `json:"detail,omitempty"`
	LatencyMs float64          `json:"latency_ms"`
	Ts        int64            `json:"ts"`
	HostID    string           `json:"host_id,omitempty"`
	Region    string           `json:"region,omitempty"`
	Diagnosis *proto.Diagnosis `json:"diagnosis,omitempty"`
}

func (c *cache) storeCheckResults(ctx context.Context, id hostIdentity, hc *hostConfig, results []proto.CheckResult) error {
	if hc == nil {
		return nil
	}
	pipe := c.rdb.Pipeline()
	for _, r := range results {
		def, ok := hc.checks[r.ID]
		if !ok {
			continue
		}
		v := storedCheckResult{OK: r.OK, Detail: r.Detail, LatencyMs: r.LatencyMs, Ts: r.TimestampMs, Diagnosis: capDiagnosis(r.Diagnosis)}
		field := id.HostID
		if def.OnProbes {
			field = "probe:" + hc.region
			v.Region = hc.region
		} else {
			v.HostID = id.HostID
		}
		b, err := json.Marshal(v)
		if err != nil {
			continue
		}
		pipe.HSet(ctx, checkResultKey+r.ID, field, b)
		// The agent diagnoses a failure once, then every few minutes: keep
		// the latest diagnosis apart so later failing runs don't drop it.
		if v.Diagnosis != nil {
			if d, err := json.Marshal(storedDiagnosis{Ts: r.TimestampMs, Diagnosis: v.Diagnosis}); err == nil {
				pipe.HSet(ctx, checkResultKey+r.ID, diagnosisPrefix+field, d)
			}
		}
		if !r.OK {
			// The last failure is kept too: the next passing run replaces
			// the current result before the alerter may have read it.
			pipe.HSet(ctx, checkResultKey+r.ID, lastFailurePrefix+field, b)
		}
		pipe.Expire(ctx, checkResultKey+r.ID, checkResultTTL)
	}
	_, err := pipe.Exec(ctx)
	return err
}

// takeLogQuota counts lines against the host's per-minute allowance and
// returns how many of n may go in.
func (c *cache) takeLogQuota(ctx context.Context, hostID string, n, perMinute int) (int, error) {
	return c.takeQuota(ctx, "logquota", hostID, n, perMinute)
}

// takeQuota counts n against a per-host, per-minute allowance named kind.
func (c *cache) takeQuota(ctx context.Context, kind, hostID string, n, perMinute int) (int, error) {
	if perMinute <= 0 || n == 0 {
		return n, nil
	}
	key := fmt.Sprintf("pulsegrid:%s:%s:%d", kind, hostID, time.Now().Unix()/60)
	used, err := c.rdb.IncrBy(ctx, key, int64(n)).Result()
	if err != nil {
		return n, err
	}
	if used == int64(n) {
		c.rdb.Expire(ctx, key, 2*time.Minute)
	}
	before := int(used) - n
	switch {
	case before >= perMinute:
		return 0, nil
	case int(used) > perMinute:
		return perMinute - before, nil
	}
	return n, nil
}

const diagnosisPrefix = "diag:"

type storedDiagnosis struct {
	Ts        int64            `json:"ts"`
	Diagnosis *proto.Diagnosis `json:"diagnosis"`
}

// capDiagnosis bounds what an agent can store with a result.
func capDiagnosis(d *proto.Diagnosis) *proto.Diagnosis {
	if d == nil {
		return nil
	}
	c := *d
	if len(c.Summary) > 500 {
		c.Summary = c.Summary[:500]
	}
	if c.DNS != nil && len(c.DNS.Addresses) > 8 {
		dns := *c.DNS
		dns.Addresses = dns.Addresses[:8]
		c.DNS = &dns
	}
	if len(c.Connect) > 8 {
		c.Connect = c.Connect[:8]
	}
	if len(c.Path) > 30 {
		c.Path = c.Path[:30]
	}
	return &c
}
