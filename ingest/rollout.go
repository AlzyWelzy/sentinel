package main

import (
	"context"
	"errors"
	"hash/fnv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Agent rollouts (api/app/services/rollout.py decides the same way): a
// server gets its account's pin, else the candidate when its bucket is in
// the candidate's share, else stable. Without a rollout row, AGENT_VERSION.
type rolloutPlan struct {
	stable, candidate string
	percent           int
	pins              map[string]string // tenant id → version
}

type rolloutCache struct {
	mu       sync.Mutex
	plan     rolloutPlan
	loadedAt time.Time
}

const rolloutTTL = 30 * time.Second

func hostBucket(hostID string) int {
	h := fnv.New32a()
	h.Write([]byte(strings.ToLower(hostID)))
	return int(h.Sum32() % 100)
}

func (p rolloutPlan) versionFor(id hostIdentity) string {
	if v := p.pins[id.TenantID]; v != "" {
		return v
	}
	if p.candidate != "" && hostBucket(id.HostID) < p.percent {
		return p.candidate
	}
	return p.stable
}

func (s *store) rolloutPlan(ctx context.Context, fallback string) (rolloutPlan, error) {
	p := rolloutPlan{stable: fallback, pins: map[string]string{}}
	var candidate *string
	err := s.pool.QueryRow(ctx,
		`SELECT stable_version, candidate_version, candidate_percent FROM agent_rollout WHERE id = 1`,
	).Scan(&p.stable, &candidate, &p.percent)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return p, err
	}
	if candidate != nil {
		p.candidate = *candidate
	}
	rows, err := s.pool.Query(ctx, `SELECT id, agent_version_pin FROM tenants WHERE agent_version_pin IS NOT NULL`)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var tenant, version string
		if err := rows.Scan(&tenant, &version); err != nil {
			return p, err
		}
		p.pins[tenant] = version
	}
	return p, rows.Err()
}

// agentVersionFor is the version this host's updater should install. On a
// database error the last plan stays in use.
func (s *server) agentVersionFor(ctx context.Context, id hostIdentity) string {
	c := &s.rollout
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loadedAt.IsZero() || time.Since(c.loadedAt) > rolloutTTL {
		plan, err := s.store.rolloutPlan(ctx, s.cfg.AgentVersion)
		if err != nil {
			s.log.Warn("agent rollout unavailable", "err", err)
			if c.loadedAt.IsZero() {
				c.plan = rolloutPlan{stable: s.cfg.AgentVersion}
			}
		} else {
			c.plan = plan
		}
		c.loadedAt = time.Now()
	}
	return c.plan.versionFor(id)
}
