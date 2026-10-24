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

	// Tags from the installer are added to any the host already has.
	err = tx.QueryRow(ctx, `
		INSERT INTO hosts (tenant_id, agent_key_id, machine_id, hostname, os, platform,
		                   platform_version, arch, agent_version, token_hash, tags)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (tenant_id, machine_id, hostname) DO UPDATE SET
		    agent_key_id = EXCLUDED.agent_key_id,
		    os = EXCLUDED.os,
		    platform = EXCLUDED.platform,
		    platform_version = EXCLUDED.platform_version,
		    arch = EXCLUDED.arch,
		    agent_version = EXCLUDED.agent_version,
		    token_hash = EXCLUDED.token_hash,
		    revoked_at = NULL,
		    tags = ARRAY(SELECT DISTINCT unnest(hosts.tags || EXCLUDED.tags) ORDER BY 1)
		RETURNING id`,
		id.TenantID, keyID, req.MachineID, req.Hostname, req.OS, req.Platform,
		req.PlatformVersion, req.Arch, req.AgentVersion, tokenHash, normalizeTags(req.Tags),
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

// touchHost records last_seen_at for usage and billing, and what the agent
// reports about the machine. Redis holds the live heartbeat; Postgres is
// updated at most once a minute per host. A new hostname is taken unless
// another host of the tenant already has it with the same machine id (the
// pair identifies a host at registration).
func (s *store) touchHost(ctx context.Context, hostID, agentVersion string, meta *proto.HostMeta) error {
	var m proto.HostMeta
	if meta != nil {
		m = *meta
	}
	var ips []string
	if meta != nil {
		ips = cleanIPs(m.IPAddresses)
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE hosts h SET
		       last_seen_at = now(),
		       agent_version = $2,
		       ip_addresses = coalesce($3::text[], h.ip_addresses),
		       cpu_cores = coalesce(nullif($4::integer, 0), h.cpu_cores),
		       memory_bytes = coalesce(nullif($5::bigint, 0), h.memory_bytes),
		       platform_version = coalesce(nullif($6::text, ''), h.platform_version),
		       hostname = CASE
		           WHEN $7::text = '' OR $7::text = h.hostname THEN h.hostname
		           WHEN EXISTS (SELECT 1 FROM hosts o
		                         WHERE o.tenant_id = h.tenant_id AND o.machine_id = h.machine_id
		                           AND o.hostname = $7::text) THEN h.hostname
		           ELSE $7::text END
		 WHERE h.id = $1
		   AND (h.last_seen_at IS NULL
		        OR h.last_seen_at < now() - interval '1 minute'
		        OR h.agent_version IS DISTINCT FROM $2)`,
		hostID, agentVersion, ips, m.CPUCores, int64(m.MemoryBytes), m.PlatformVersion, cleanHostname(m.Hostname))
	return err
}

// watches returns the processes and services the host's enabled alert rules
// check: rules for every host, for this host, or for one of its tags.
func (s *store) watches(ctx context.Context, id hostIdentity) (processes, services []string, err error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT r.kind, r.target
		  FROM alert_rules r JOIN hosts h ON h.id = $1 AND h.tenant_id = r.tenant_id
		 WHERE r.tenant_id = $2 AND r.enabled AND r.kind IN ('process_down', 'service_down')
		   AND (r.host_id IS NULL OR r.host_id = h.id)
		   AND (r.tag IS NULL OR r.tag = ANY (h.tags))
		 ORDER BY r.kind, r.target`, id.HostID, id.TenantID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind, target string
		if err := rows.Scan(&kind, &target); err != nil {
			return nil, nil, err
		}
		if kind == "process_down" {
			processes = append(processes, target)
		} else {
			services = append(services, target)
		}
	}
	return processes, services, rows.Err()
}
