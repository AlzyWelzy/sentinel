package main

// Network devices: switches, firewalls and other gear an agent polls over
// SNMP for its site. The device is a hosts row (kind 'network') whose
// poller_host_id is that agent's host. Ingest hands the agent its devices
// (credentials opened with CREDENTIALS_KEY) and files what the polls find:
// samples under the device's own host_id, its state, interfaces and LLDP
// neighbours. Text from devices is untrusted: it's cleaned and capped.

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/AlzyWelzy/sentinel/proto"
)

const (
	maxDeviceInterfaces = 4096
	maxDeviceNeighbors  = 1024
	maxDevicesPerPoller = 2000
)

type deviceRow struct {
	ID, Address, Profile, Version, Secret string
}

// pollerDevices are the network devices this host polls.
func (s *store) pollerDevices(ctx context.Context, id hostIdentity) ([]deviceRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT h.id::text, h.address, coalesce(h.profile, ''), c.version, c.secret
		  FROM hosts h
		  JOIN snmp_credentials c ON c.id = h.snmp_credential_id AND c.tenant_id = h.tenant_id
		 WHERE h.tenant_id = $1 AND h.poller_host_id = $2 AND h.kind = 'network'
		   AND h.revoked_at IS NULL AND h.paused_at IS NULL
		 ORDER BY h.created_at
		 LIMIT $3`, id.TenantID, id.HostID, maxDevicesPerPoller)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (deviceRow, error) {
		var d deviceRow
		return d, r.Scan(&d.ID, &d.Address, &d.Profile, &d.Version, &d.Secret)
	})
}

// networkDevices builds the poller's device list. A credential that can't be
// opened (CREDENTIALS_KEY missing or changed) leaves its devices out, with a
// log line, rather than failing the whole config.
func (s *server) networkDevices(ctx context.Context, id hostIdentity) ([]proto.NetworkDevice, map[string]bool, error) {
	rows, err := s.store.pollerDevices(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	var out []proto.NetworkDevice
	ids := map[string]bool{}
	for _, r := range rows {
		var cred proto.SNMPCredential
		if err := openSealed(s.cfg.CredentialsKey, r.Secret, &cred); err != nil {
			s.log.Error("device credential unreadable", "device_id", r.ID, "err", err)
			continue
		}
		cred.Version = r.Version
		out = append(out, proto.NetworkDevice{ID: r.ID, Address: r.Address, Profile: r.Profile, Credential: cred})
		ids[r.ID] = true
	}
	return out, ids, nil
}

// devicePollState is what's kept of the last poll in hosts.device.
type devicePollState struct {
	OK         bool                 `json:"ok"`
	Profile    string               `json:"profile,omitempty"`
	DurationMs int64                `json:"duration_ms,omitempty"`
	System     *proto.NetworkSystem `json:"system,omitempty"`
}

// saveNetworkPolls files what polls found. A poll older than the device's
// last one (a replay from the agent's spool) changes nothing.
func (s *store) saveNetworkPolls(ctx context.Context, id hostIdentity, batches []proto.Batch, devices map[string]bool) (seen map[string]time.Time, err error) {
	seen = map[string]time.Time{}
	for _, b := range batches {
		at := time.UnixMilli(b.TimestampMs)
		for _, p := range b.Network {
			if !devices[p.DeviceID] {
				continue
			}
			if err := s.saveNetworkPoll(ctx, id, p, at); err != nil {
				return seen, err
			}
			if p.OK && at.After(seen[p.DeviceID]) {
				seen[p.DeviceID] = at
			}
		}
	}
	return seen, nil
}

func (s *store) saveNetworkPoll(ctx context.Context, id hostIdentity, p proto.NetworkPoll, at time.Time) error {
	st := devicePollState{OK: p.OK, Profile: cleanField(p.Profile, 100), DurationMs: p.DurationMs}
	var sysName, vendor string
	if p.System != nil {
		sys := *p.System
		sys.Descr = cleanField(sys.Descr, 1000)
		sys.ObjectID = cleanField(sys.ObjectID, 200)
		sys.Name = cleanField(sys.Name, 255)
		sys.Contact = cleanField(sys.Contact, 255)
		sys.Location = cleanField(sys.Location, 255)
		sys.Vendor = cleanField(sys.Vendor, 100)
		st.System = &sys
		sysName, vendor = sys.Name, sys.Vendor
	}
	state, _ := json.Marshal(st)
	var inventory []byte
	osVersion := ""
	if p.Inventory != nil {
		inv := map[string]string{}
		for k, v := range p.Inventory {
			if len(inv) >= 100 {
				break
			}
			inv[cleanField(k, 64)] = cleanField(v, 500)
		}
		inventory, _ = json.Marshal(inv)
		osVersion = inv["os_version"]
	}
	errText := ""
	if !p.OK || p.Error != "" {
		errText = cleanField(p.Error, 1000)
		if errText == "" {
			errText = "No SNMP answer"
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// The device's name follows its sysName until someone names it.
	tag, err := tx.Exec(ctx, `
		UPDATE hosts SET
		       device = device || $4::jsonb
		              || CASE WHEN $5::jsonb IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('inventory', $5::jsonb) END
		              || CASE WHEN $8 THEN jsonb_build_object('last_ok_at', $3::timestamptz) ELSE '{}'::jsonb END,
		       device_error = nullif($6, ''),
		       device_polled_at = $3,
		       os = 'network',
		       platform = CASE WHEN $7 <> '' THEN $7 ELSE platform END,
		       platform_version = CASE WHEN $9 <> '' THEN $9 ELSE platform_version END,
		       hostname = CASE WHEN hostname = address AND $10 <> '' THEN $10 ELSE hostname END,
		       last_seen_at = CASE WHEN $8 THEN greatest(last_seen_at, $3) ELSE last_seen_at END
		 WHERE id = $1 AND tenant_id = $2 AND poller_host_id = $11 AND kind = 'network'
		   AND (device_polled_at IS NULL OR device_polled_at <= $3)`,
		p.DeviceID, id.TenantID, at, string(state), nullJSON(inventory), errText, vendor, p.OK, osVersion,
		cleanHostname(sysName), id.HostID)
	if err != nil || tag.RowsAffected() == 0 {
		return err // stale or no longer this poller's: nothing to do
	}
	if p.Full && p.OK {
		if err := replaceInterfaces(ctx, tx, id.TenantID, p.DeviceID, p.Interfaces); err != nil {
			return err
		}
		if err := replaceLinks(ctx, tx, id.TenantID, p.DeviceID, p.Neighbors); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func nullJSON(b []byte) any {
	if b == nil {
		return nil
	}
	return string(b)
}

// replaceInterfaces makes the device's interface list what the inventory poll
// found, keeping billing tags on interfaces that are still there.
func replaceInterfaces(ctx context.Context, tx pgx.Tx, tenantID, deviceID string, ifs []proto.NetworkInterface) error {
	if len(ifs) > maxDeviceInterfaces {
		ifs = ifs[:maxDeviceInterfaces]
	}
	keep := make([]int32, 0, len(ifs))
	batch := &pgx.Batch{}
	for _, i := range ifs {
		if i.Index <= 0 || i.Index > 1<<31-1 {
			continue
		}
		keep = append(keep, int32(i.Index))
		speed := int64(min(i.SpeedBps, 1<<62))
		batch.Queue(`
			INSERT INTO network_interfaces (tenant_id, host_id, ifindex, name, descr, alias, type, speed_bps, mtu, mac, admin_up, oper_status, updated_at)
			VALUES ($1, $2, $3, $4, nullif($5, ''), nullif($6, ''), $7, $8, $9, nullif($10, ''), $11, $12, now())
			ON CONFLICT (host_id, ifindex) DO UPDATE SET
			       name = excluded.name, descr = excluded.descr, alias = excluded.alias, type = excluded.type,
			       speed_bps = excluded.speed_bps, mtu = excluded.mtu, mac = excluded.mac,
			       admin_up = excluded.admin_up, oper_status = excluded.oper_status, updated_at = now()`,
			tenantID, deviceID, i.Index, orDefault(cleanField(i.Name, 255), "if"+itoa(i.Index)), cleanField(i.Descr, 255),
			cleanField(i.Alias, 255), i.Type, speed, i.MTU, cleanField(i.MAC, 64), i.AdminUp, i.OperStatus)
	}
	batch.Queue(`DELETE FROM network_interfaces WHERE host_id = $1 AND tenant_id = $2 AND NOT (ifindex = ANY($3))`,
		deviceID, tenantID, keep)
	return tx.SendBatch(ctx, batch).Close()
}

// replaceLinks stores the device's LLDP neighbours and resolves each to a
// known device or server by name, management address or chassis MAC.
func replaceLinks(ctx context.Context, tx pgx.Tx, tenantID, deviceID string, nbs []proto.NetworkNeighbor) error {
	if len(nbs) > maxDeviceNeighbors {
		nbs = nbs[:maxDeviceNeighbors]
	}
	batch := &pgx.Batch{}
	batch.Queue(`DELETE FROM network_links WHERE host_id = $1 AND tenant_id = $2`, deviceID, tenantID)
	for _, n := range nbs {
		local := cleanField(n.LocalPort, 255)
		if local == "" {
			continue
		}
		mgmt := cleanField(n.RemoteMgmtAddr, 100)
		if ip := net.ParseIP(mgmt); ip == nil {
			mgmt = ""
		}
		batch.Queue(`
			INSERT INTO network_links (tenant_id, host_id, local_port, remote_sys_name, remote_port_id, remote_port_desc, remote_chassis_id, remote_mgmt_addr, seen_at)
			VALUES ($1, $2, $3, $4, $5, nullif($6, ''), $7, nullif($8, ''), now())
			ON CONFLICT (host_id, local_port, remote_chassis_id, remote_port_id) DO NOTHING`,
			tenantID, deviceID, local, cleanField(n.RemoteSysName, 255), cleanField(n.RemotePortID, 255),
			cleanField(n.RemotePortDesc, 255), strings.ToLower(cleanField(n.RemoteChassis, 100)), mgmt)
	}
	batch.Queue(`
		UPDATE network_links l SET remote_host_id = (
		       SELECT h.id FROM hosts h
		        WHERE h.tenant_id = l.tenant_id AND h.id <> l.host_id AND h.revoked_at IS NULL
		          AND ((l.remote_sys_name <> '' AND (lower(h.hostname) = lower(l.remote_sys_name)
		                OR lower(h.device->'system'->>'name') = lower(l.remote_sys_name)))
		            OR (l.remote_mgmt_addr IS NOT NULL AND (h.address = l.remote_mgmt_addr
		                OR split_part(h.address, ':', 1) = l.remote_mgmt_addr
		                OR l.remote_mgmt_addr = ANY (h.ip_addresses)))
		            OR (l.remote_chassis_id <> '' AND EXISTS (
		                SELECT 1 FROM network_interfaces i
		                 WHERE i.host_id = h.id AND lower(i.mac) = l.remote_chassis_id))
		            -- a server's NIC announcing itself by its address
		            OR l.remote_chassis_id = ANY (h.macs)
		            OR lower(l.remote_port_id) = ANY (h.macs))
		        ORDER BY (h.kind = 'network') DESC, h.created_at
		        LIMIT 1)
		 WHERE l.host_id = $1 AND l.tenant_id = $2`, deviceID, tenantID)
	return tx.SendBatch(ctx, batch).Close()
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
