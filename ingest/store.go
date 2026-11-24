package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AlzyWelzy/sentinel/proto"
)

// Ingest connects as sentinel_service, which bypasses RLS: an agent has no
// tenant until its key or token has been looked up. Tenant scoping here comes
// from those lookups, and every row written takes tenant_id from them, never
// from the agent's request.

var (
	errUnknownCredential = errors.New("unknown or revoked credential")
	errTenantSuspended   = errors.New("tenant suspended")
	errHostLimit         = errors.New("the plan's server limit is reached")
)

type hostIdentity struct {
	HostID   string
	TenantID string
	Active   bool
}

type store struct {
	pool *pgxpool.Pool
	// billing: plan limits apply (Razorpay is set up). Off, no limits.
	billing bool
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

	var keyID, tenantStatus, plan string
	err = tx.QueryRow(ctx, `
		SELECT ak.id, ak.tenant_id, t.status, t.plan
		  FROM agent_keys ak JOIN tenants t ON t.id = ak.tenant_id
		 WHERE ak.key_hash = $1 AND ak.revoked_at IS NULL
		   FOR SHARE OF t`, keyHash,
	).Scan(&keyID, &id.TenantID, &tenantStatus, &plan)
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
	if limit := proto.PlanByID(plan).Limits.Hosts; s.billing && limit != nil && errors.Is(err, pgx.ErrNoRows) {
		var n int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM hosts WHERE tenant_id = $1 AND revoked_at IS NULL`, id.TenantID,
		).Scan(&n); err != nil {
			return id, "", err
		}
		if n >= *limit {
			return id, "", errHostLimit
		}
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

// logsAccount is the tenant's VictoriaLogs AccountID.
func (s *store) logsAccount(ctx context.Context, tenantID string) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `SELECT logs_account_id FROM tenants WHERE id = $1`, tenantID).Scan(&id)
	return id, err
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
func (s *store) touchHost(ctx context.Context, hostID, agentVersion, publicIP string, meta *proto.HostMeta) error {
	var m proto.HostMeta
	if meta != nil {
		m = *meta
	}
	var ips, macs []string
	if meta != nil {
		ips = cleanIPs(m.IPAddresses)
		macs = cleanMACs(m.MACs)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE hosts h SET
		       last_seen_at = now(),
		       agent_version = $2,
		       ip_addresses = coalesce($3::text[], h.ip_addresses),
		       macs = coalesce($9::text[], h.macs),
		       trap_port = CASE WHEN $10::boolean THEN nullif($11::integer, 0) ELSE h.trap_port END,
		       public_ip = coalesce(nullif($8::text, ''), h.public_ip),
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
		        OR h.agent_version IS DISTINCT FROM $2
		        OR ($10::boolean AND h.trap_port IS DISTINCT FROM nullif($11::integer, 0))
		        OR (nullif($8::text, '') IS NOT NULL AND h.public_ip IS DISTINCT FROM $8::text))`,
		hostID, agentVersion, ips, m.CPUCores, int64(m.MemoryBytes), m.PlatformVersion, cleanHostname(m.Hostname), publicIP, macs,
		meta != nil, min(max(m.TrapPort, 0), 65535))
	if err != nil || len(macs) == 0 || tag.RowsAffected() == 0 {
		return err
	}
	// A switch already listing one of these as an LLDP neighbour now knows
	// which server it is (devices re-resolve on their own inventory polls).
	_, err = s.pool.Exec(ctx, `
		UPDATE network_links l SET remote_host_id = h.id
		  FROM hosts h
		 WHERE h.id = $1 AND l.tenant_id = h.tenant_id AND l.host_id <> h.id
		   AND l.remote_host_id IS NULL
		   AND (l.remote_chassis_id = ANY ($2::text[]) OR lower(l.remote_port_id) = ANY ($2::text[]))`,
		hostID, macs)
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

// checkDef is a check as handed to one host, with the tenant whose check it
// is: the host's own tenant, or for public probe checks, the check owner's.
type checkDef struct {
	proto.Check
	TenantID string
	OnProbes bool
}

// hostChecks returns the checks this host runs: its own tenant's checks for
// it or its tags, and, if it's a probe, every active tenant's probe checks
// for its region. Also returns the host's probe region ("" if not a probe).
func (s *store) hostChecks(ctx context.Context, id hostIdentity) ([]checkDef, string, error) {
	var region *string
	if err := s.pool.QueryRow(ctx, `SELECT probe_region FROM hosts WHERE id = $1`, id.HostID).Scan(&region); err != nil {
		return nil, "", err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT c.id, c.tenant_id, c.type, c.target, c.params, c.interval_seconds, c.on_probes
		  FROM checks c
		  JOIN hosts h ON h.id = $1
		  JOIN tenants t ON t.id = c.tenant_id AND t.status = 'active'
		 WHERE c.enabled
		   AND ((NOT c.on_probes AND c.tenant_id = h.tenant_id
		         AND (c.host_id = h.id OR c.tag = ANY (h.tags)))
		        OR (c.on_probes AND h.probe_region IS NOT NULL
		            AND (cardinality(c.probe_regions) = 0 OR h.probe_region = ANY (c.probe_regions))))
		 ORDER BY c.id`, id.HostID)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var out []checkDef
	for rows.Next() {
		var c checkDef
		var params map[string]any
		if err := rows.Scan(&c.ID, &c.TenantID, &c.Type, &c.Target, &params, &c.IntervalSeconds, &c.OnProbes); err != nil {
			return nil, "", err
		}
		c.Params = map[string]string{}
		for k, v := range params {
			c.Params[k] = fmt.Sprint(v)
		}
		if c.OnProbes {
			// Probes run on our network: they must never reach private
			// addresses on a customer's behalf. The agent enforces this
			// when it connects, so DNS can't be used to slip past it.
			c.Params["public_only"] = "true"
		}
		out = append(out, c)
	}
	r := ""
	if region != nil {
		r = *region
	}
	return out, r, rows.Err()
}

// pendingActions returns actions waiting for this host. Older than an hour
// they're expired instead: a restart nobody saw happen shouldn't run later.
func (s *store) pendingActions(ctx context.Context, hostID string) ([]proto.ActionRequest, error) {
	if _, err := s.pool.Exec(ctx, `
		UPDATE host_actions SET status = 'expired', finished_at = now()
		 WHERE host_id = $1 AND status = 'pending' AND created_at < now() - interval '1 hour'`, hostID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, name FROM host_actions
		 WHERE host_id = $1 AND status = 'pending' ORDER BY created_at LIMIT 20`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []proto.ActionRequest
	for rows.Next() {
		var a proto.ActionRequest
		if err := rows.Scan(&a.ID, &a.Name); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

var actionStatuses = map[string]bool{"succeeded": true, "failed": true, "refused": true}

// finishActions records results the host reports for its own actions, and
// notes them on the incident that triggered them, if any.
func (s *store) finishActions(ctx context.Context, hostID string, results []proto.ActionResult) error {
	for _, r := range results {
		if !actionStatuses[r.Status] {
			continue
		}
		out := r.Output
		if len(out) > 4096 {
			out = out[:4096]
		}
		_, err := s.pool.Exec(ctx, `
			WITH a AS (
				UPDATE host_actions SET status = $3, exit_code = $4, output = $5, finished_at = now()
				 WHERE id = $1::uuid AND host_id = $2 AND status = 'pending'
				RETURNING tenant_id, incident_id, name
			)
			INSERT INTO incident_events (tenant_id, incident_id, kind, message, actor)
			SELECT tenant_id, incident_id, 'action',
			       'Action ' || name || ' ' || $3 || CASE WHEN $5 <> '' THEN ': ' || left($5, 500) ELSE '' END,
			       'agent'
			  FROM a WHERE incident_id IS NOT NULL`,
			r.ID, hostID, r.Status, r.ExitCode, out)
		if err != nil && !strings.Contains(err.Error(), "invalid input syntax for type uuid") {
			return err
		}
	}
	return nil
}

// saveInventory stores the latest inventory and remembers which packages
// changed since the previous one (the last 200 changes are kept).
func (s *store) saveInventory(ctx context.Context, id hostIdentity, inv *proto.Inventory) error {
	data, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var prevData []byte
	var prevChanges []byte
	err = tx.QueryRow(ctx, `SELECT data, changes FROM host_inventory WHERE host_id = $1 FOR UPDATE`, id.HostID).
		Scan(&prevData, &prevChanges)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	var changes []packageChange
	if len(prevChanges) > 0 {
		json.Unmarshal(prevChanges, &changes)
	}
	if len(prevData) > 0 {
		var prev proto.Inventory
		if json.Unmarshal(prevData, &prev) == nil && len(inv.Packages) > 0 {
			changes = append(diffPackages(prev.Packages, inv.Packages, time.Now()), changes...)
			if len(changes) > 200 {
				changes = changes[:200]
			}
		}
	}
	if changes == nil {
		changes = []packageChange{}
	}
	ch, _ := json.Marshal(changes)
	if _, err := tx.Exec(ctx, `
		INSERT INTO host_inventory (host_id, tenant_id, data, changes, updated_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (host_id) DO UPDATE SET data = EXCLUDED.data, changes = EXCLUDED.changes, updated_at = now()`,
		id.HostID, id.TenantID, data, ch); err != nil {
		return err
	}
	allowed := inv.AllowedActions
	if allowed == nil {
		allowed = []string{}
	}
	if _, err := tx.Exec(ctx, `UPDATE hosts SET allowed_actions = $2 WHERE id = $1`, id.HostID, allowed); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type packageChange struct {
	Name   string `json:"name"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Change string `json:"change"` // installed | removed | upgraded
	At     int64  `json:"at"`
}

func diffPackages(prev, cur []proto.Package, now time.Time) []packageChange {
	old := map[string]string{}
	for _, p := range prev {
		old[p.Name] = p.Version
	}
	var out []packageChange
	seen := map[string]bool{}
	for _, p := range cur {
		seen[p.Name] = true
		v, ok := old[p.Name]
		switch {
		case !ok:
			out = append(out, packageChange{Name: p.Name, To: p.Version, Change: "installed", At: now.Unix()})
		case v != p.Version:
			out = append(out, packageChange{Name: p.Name, From: v, To: p.Version, Change: "upgraded", At: now.Unix()})
		}
	}
	for _, p := range prev {
		if !seen[p.Name] {
			out = append(out, packageChange{Name: p.Name, From: p.Version, Change: "removed", At: now.Unix()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
