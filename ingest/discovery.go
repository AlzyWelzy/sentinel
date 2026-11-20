package main

// Network discovery: the API asks for a range to be scanned by one of the
// organisation's servers (Redis, 24 h); that server's agent gets it in its
// config, scans once and reports progress, which lands back in Redis for
// the API to show. A result for a discovery another agent owns is ignored.

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

const (
	discoveryKey       = "pg:netdisc:"        // + id: hash, shared with the API
	discoveryPollerKey = "pg:netdisc:poller:" // + poller host id: set of ids
	discoveryTTL       = 24 * time.Hour
	maxDiscoveryFound  = 1024
)

// discoveriesFor are the scans waiting for this host.
func (s *server) discoveriesFor(ctx context.Context, id hostIdentity) []proto.NetworkDiscovery {
	ids, err := s.cache.rdb.SMembers(ctx, discoveryPollerKey+id.HostID).Result()
	if err != nil || len(ids) == 0 {
		return nil
	}
	var out []proto.NetworkDiscovery
	for _, did := range ids {
		h, err := s.cache.rdb.HGetAll(ctx, discoveryKey+did).Result()
		if err != nil || h["tenant"] != id.TenantID || h["poller"] != id.HostID || h["status"] == "done" {
			continue
		}
		var version, secret string
		if err := s.store.pool.QueryRow(ctx,
			`SELECT version, secret FROM snmp_credentials WHERE id = $1 AND tenant_id = $2`,
			h["credential"], id.TenantID).Scan(&version, &secret); err != nil {
			continue
		}
		var cred proto.SNMPCredential
		if err := openSealed(s.cfg.CredentialsKey, secret, &cred); err != nil || version == "proxmox" {
			continue
		}
		cred.Version = version
		port, _ := strconv.Atoi(h["port"])
		out = append(out, proto.NetworkDiscovery{ID: did, CIDR: h["cidr"], Port: port, Credential: cred})
	}
	return out
}

// saveDiscoveries records progress reported by the agent.
func (s *server) saveDiscoveries(ctx context.Context, id hostIdentity, batches []proto.Batch) {
	for _, b := range batches {
		for _, r := range b.Discoveries {
			key := discoveryKey + r.ID
			h, err := s.cache.rdb.HMGet(ctx, key, "tenant", "poller", "status").Result()
			if err != nil || len(h) != 3 || h[0] != id.TenantID || h[1] != id.HostID || h[2] == "done" {
				continue
			}
			found := r.Found
			if len(found) > maxDiscoveryFound {
				found = found[:maxDiscoveryFound]
			}
			for i := range found {
				found[i].Address = cleanField(found[i].Address, 100)
				found[i].SysName = cleanField(found[i].SysName, 255)
				found[i].SysDescr = cleanField(found[i].SysDescr, 300)
				found[i].ObjectID = cleanField(found[i].ObjectID, 200)
				found[i].Profile = cleanField(found[i].Profile, 100)
				found[i].Vendor = cleanField(found[i].Vendor, 100)
			}
			js, _ := json.Marshal(found)
			status := "running"
			if r.Done {
				status = "done"
			}
			s.cache.rdb.HSet(ctx, key, "status", status, "scanned", r.Scanned, "total", r.Total,
				"found", string(js), "error", cleanField(r.Error, 300), "updated", time.Now().Unix())
			s.cache.rdb.Expire(ctx, key, discoveryTTL)
			if r.Done {
				s.configs.forget(id.HostID) // drop it from the agent's config
			}
		}
	}
}
