package main

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/example-org/pulsegrid/proto"
)

// Ingest connects as pulsegrid_service, which bypasses RLS: an agent has no
// tenant until its key or token has been looked up. Tenant scoping here comes
// from those lookups, and every row written takes tenant_id from them, never
// from the agent's request.

var (
	errUnknownCredential = errors.New("unknown or revoked credential")
	errTenantSuspended   = errors.New("tenant suspended")
)

type hostIdentity struct {
	HostID   string
	TenantID string
	Active   bool
}

type store struct {
	pool *pgxpool.Pool
}

// register exchanges an install key for a host record. Re-running it on the
// same machine (same tenant, machine_id and hostname) rotates that host's
// token instead of creating a duplicate; the old token hash is returned so its
// cache entry can go. Hostname is part of the key because VMs cloned from one
// template often share a machine_id.
func (s *store) register(
	ctx context.Context, keyHash, tokenHash string, req proto.RegisterRequest,
) (id hostIdentity, oldTokenHash string, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return id, "", err
	}
	defer tx.Rollback(ctx)

	var keyID, tenantStatus string
	err = tx.QueryRow(ctx, `
		SELECT ak.id, ak.tenant_id, t.status
		  FROM agent_keys ak JOIN tenants t ON t.id = ak.tenant_id
		 WHERE ak.key_hash = $1 AND ak.revoked_at IS NULL`, keyHash,
	).Scan(&keyID, &id.TenantID, &tenantStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return id, "", errUnknownCredential
	}
	if err != nil {
		return id, "", err
	}
	if tenantStatus != "active" {
		return id, "", errTenantSuspended
	}

	err = tx.QueryRow(ctx, `
		SELECT token_hash FROM hosts
		 WHERE tenant_id = $1 AND machine_id = $2 AND hostname = $3 FOR UPDATE`,
		id.TenantID, req.MachineID, req.Hostname,
	).Scan(&oldTokenHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return id, "", err
	}

	err = tx.QueryRow(ctx, `
		INSERT INTO hosts (tenant_id, agent_key_id, machine_id, hostname, os, platform,
		                   platform_version, arch, agent_version, token_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (tenant_id, machine_id, hostname) DO UPDATE SET
		    agent_key_id = EXCLUDED.agent_key_id,
		    os = EXCLUDED.os,
		    platform = EXCLUDED.platform,
		    platform_version = EXCLUDED.platform_version,
		    arch = EXCLUDED.arch,
		    agent_version = EXCLUDED.agent_version,
		    token_hash = EXCLUDED.token_hash,
		    revoked_at = NULL
		RETURNING id`,
		id.TenantID, keyID, req.MachineID, req.Hostname, req.OS, req.Platform,
		req.PlatformVersion, req.Arch, req.AgentVersion, tokenHash,
	).Scan(&id.HostID)
	if err != nil {
		return id, "", err
	}
	id.Active = true
	return id, oldTokenHash, tx.Commit(ctx)
}

func (s *store) lookupHost(ctx context.Context, tokenHash string) (hostIdentity, error) {
	var id hostIdentity
	var status string
	err := s.pool.QueryRow(ctx, `
		SELECT h.id, h.tenant_id, t.status
		  FROM hosts h JOIN tenants t ON t.id = h.tenant_id
		 WHERE h.token_hash = $1 AND h.revoked_at IS NULL`, tokenHash,
	).Scan(&id.HostID, &id.TenantID, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return id, errUnknownCredential
	}
	id.Active = status == "active"
	return id, err
}

// touchHost records last_seen_at for usage and billing. Redis holds the live
// heartbeat; Postgres is updated at most once a minute per host.
func (s *store) touchHost(ctx context.Context, hostID, agentVersion string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE hosts SET last_seen_at = now(), agent_version = $2
		 WHERE id = $1
		   AND (last_seen_at IS NULL
		        OR last_seen_at < now() - interval '1 minute'
		        OR agent_version IS DISTINCT FROM $2)`, hostID, agentVersion)
	return err
}
