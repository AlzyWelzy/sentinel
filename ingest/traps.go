package main

// SNMP traps the agent received from its devices. Each is classified with
// netmon/traps and stored in network_traps under the device that sent it,
// found by address (the device's polled address) or, for a FortiGate sending
// from another interface, by the sysName the trap carries. A trap from any
// other sender is recorded under the poller only and never alerts. The same
// trap again within a minute (a flood) updates the previous row's repeat
// count instead of adding rows.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/AlzyWelzy/sentinel/netmon/traps"
	"github.com/AlzyWelzy/sentinel/proto"
)

const (
	maxTrapsPerRequest = 2000
	trapRepeatWindow   = time.Minute
	maxTrapVarbinds    = 64
)

type trapDevice struct {
	id, address, hostname string
}

func (s *store) trapDevices(ctx context.Context, id hostIdentity) ([]trapDevice, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT h.id::text, coalesce(h.address, ''), h.hostname
		  FROM hosts h
		 WHERE h.tenant_id = $1 AND h.poller_host_id = $2 AND h.kind = 'network' AND h.revoked_at IS NULL`,
		id.TenantID, id.HostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []trapDevice
	for rows.Next() {
		var d trapDevice
		if err := rows.Scan(&d.id, &d.address, &d.hostname); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// addressHost strips a port from a device address ("10.0.0.1:1161").
func addressHost(a string) string {
	if h, _, err := net.SplitHostPort(a); err == nil {
		return h
	}
	return a
}

// trapDeviceFor finds the device a trap came from.
func trapDeviceFor(devices []trapDevice, t proto.Trap) string {
	for _, d := range devices {
		if addressHost(d.address) == t.Source {
			return d.id
		}
	}
	name := strings.TrimSpace(strings.Trim(t.Varbinds["1.3.6.1.2.1.1.5.0"], `"`))
	if name != "" {
		for _, d := range devices {
			if strings.EqualFold(d.hostname, name) {
				return d.id
			}
		}
	}
	return ""
}

func hasTraps(req proto.MetricsRequest) bool {
	for _, b := range req.Batches {
		if len(b.Traps) > 0 {
			return true
		}
	}
	return false
}

// saveTraps stores the traps in this push.
func (s *store) saveTraps(ctx context.Context, id hostIdentity, batches []proto.Batch) (int, error) {
	devices, err := s.trapDevices(ctx, id)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, b := range batches {
		for _, t := range b.Traps {
			if n >= maxTrapsPerRequest {
				return n, nil
			}
			if err := s.saveTrap(ctx, id, devices, t); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

func (s *store) saveTrap(ctx context.Context, id hostIdentity, devices []trapDevice, t proto.Trap) error {
	vb := map[string]string{}
	for k, v := range t.Varbinds {
		if len(vb) >= maxTrapVarbinds {
			break
		}
		vb[cleanField(k, 200)] = cleanField(v, 1000)
	}
	oid := cleanField(t.OID, 200)
	r := traps.Classify(oid, vb) // also drops a community varbind
	if r.Type != nil {
		oid = r.Type.OID // v1 and v2c copies of one trap share history
	}
	labels := map[string]string{}
	for k, v := range r.Labels {
		labels[k] = cleanField(v, 300)
	}
	at := time.UnixMilli(t.TimeMs)
	if now := time.Now(); t.TimeMs <= 0 || at.After(now.Add(time.Minute)) || at.Before(now.Add(-48*time.Hour)) {
		at = now
	}
	var hostID any
	devID := trapDeviceFor(devices, t)
	if devID != "" {
		hostID = devID
	}
	action, rule := string(r.Action), any(nil)
	if devID == "" {
		action = string(traps.Event) // unknown senders never alert
	} else if r.Rule != "" {
		rule = r.Rule
	}
	sev := r.Severity
	if action != string(traps.Open) && sev != "info" && r.Type != nil && r.Type.Rule != "" {
		sev = "info" // a clear, or a trap whose alert isn't opened
	}
	labelsJSON, _ := json.Marshal(labels)
	vbJSON, _ := json.Marshal(vb)
	identity := cleanField(r.Identity, 500)
	source := cleanField(t.Source, 100)

	// A repeat within the window updates the previous row.
	tag, err := s.pool.Exec(ctx, `
		UPDATE network_traps SET repeats = repeats + 1, last_at = greatest(last_at, $7), labels = $8
		 WHERE id = (SELECT id FROM network_traps
		              WHERE tenant_id = $1 AND host_id IS NOT DISTINCT FROM $2::uuid AND source = $3
		                AND oid = $4 AND identity = $5 AND action = $6
		                AND last_at > $7::timestamptz - $9::interval
		              ORDER BY last_at DESC LIMIT 1)`,
		id.TenantID, hostID, source, oid, identity, action, at, labelsJSON, fmt.Sprintf("%d seconds", int(trapRepeatWindow.Seconds())))
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO network_traps (tenant_id, host_id, poller_host_id, source, version, oid, name, title,
		                           action, rule, identity, severity, labels, varbinds, received_at, last_at)
		VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $15)`,
		id.TenantID, hostID, id.HostID, source, cleanField(t.Version, 5), oid, cleanField(r.Name, 200),
		cleanField(r.Title, 300), action, rule, identity, sev, labelsJSON, vbJSON, at)
	return err
}
