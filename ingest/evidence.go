package main

// POST /v1/evidence: IPDR records from an organisation's evidence
// collector. Accepted only from that one server while the organisation has
// IPDR on; parsed and written to ClickHouse under the organisation, each
// row expiring after its retention. A batch delivered twice (the agent
// retried after a timeout) is stored once.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/AlzyWelzy/sentinel/proto"
)

const (
	maxEvidenceItems = 20000
	evidenceDedupTTL = 72 * time.Hour
	evidenceStatsKey = "pg:evidence:stats:" // + tenant id; read by the API
)

type evidenceSettings struct {
	Enabled       bool
	RetentionDays int
	CollectorID   string
	Allow         []string
}

func (s *store) evidenceSettings(ctx context.Context, tenantID string) (evidenceSettings, error) {
	var e evidenceSettings
	var collector *string
	err := s.pool.QueryRow(ctx, `
		SELECT ipdr_enabled, ipdr_retention_days, ipdr_collector_host_id::text, ipdr_allow
		  FROM tenants WHERE id = $1`, tenantID).Scan(&e.Enabled, &e.RetentionDays, &collector, &e.Allow)
	if errors.Is(err, pgx.ErrNoRows) {
		return e, nil
	}
	if collector != nil {
		e.CollectorID = *collector
	}
	return e, err
}

// evidenceConfig is what the collector's agent should listen on.
func (s *server) evidenceConfig(ctx context.Context, id hostIdentity) *proto.EvidenceConfig {
	e, err := s.store.evidenceSettings(ctx, id.TenantID)
	if err != nil || !e.Enabled || e.CollectorID != id.HostID {
		return nil
	}
	p := s.cfg.EvidencePorts
	return &proto.EvidenceConfig{SyslogUDP: p[0], SyslogTCP: p[1], SFlow: p[2], NetFlow: p[3], IPFIX: p[4],
		Allow: e.Allow, FDBIntervalSeconds: 900}
}

func (s *server) handleEvidence(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.ch == nil {
		httpError(w, http.StatusServiceUnavailable, "evidence store not configured")
		return
	}
	settings, err := s.store.evidenceSettings(r.Context(), id.TenantID)
	if err != nil {
		httpError(w, http.StatusServiceUnavailable, "try again later")
		return
	}
	if !settings.Enabled || settings.CollectorID != id.HostID {
		// 403: the agent keeps the batch, so turning IPDR back on (or
		// picking this server again) delivers what it holds.
		httpError(w, http.StatusForbidden, "this server isn't the organisation's evidence collector")
		return
	}
	var b proto.EvidenceBatch
	if err := decodeBody(r, &b); err != nil {
		bodyError(w, err)
		return
	}
	if len(b.Logs)+len(b.Flows)+len(b.FDB) > maxEvidenceItems {
		httpError(w, http.StatusRequestEntityTooLarge, "too many records in one batch")
		return
	}
	if b.ID != "" {
		fresh, err := s.cache.rdb.SetNX(r.Context(), "pg:evidence:batch:"+id.TenantID+":"+b.ID, 1, evidenceDedupTTL).Result()
		if err == nil && !fresh {
			writeJSON(w, http.StatusOK, proto.EvidenceResponse{Accepted: 0})
			return
		}
	}
	hc, _ := s.loadHostConfig(r.Context(), id)
	devByIP := map[netip.Addr]string{}
	if hc != nil {
		for _, d := range hc.cfg.Devices {
			host := d.Address
			if h, _, err := net.SplitHostPort(d.Address); err == nil {
				host = h
			}
			if a, err := netip.ParseAddr(host); err == nil {
				devByIP[a.Unmap()] = d.ID
			}
		}
	}
	expires := time.Now().UTC().AddDate(0, 0, max(settings.RetentionDays, 1)).Format("2006-01-02")
	rows := buildEvidenceRows(id.TenantID, expires, b, devByIP, func(dev string) bool { return hc != nil && hc.devices[dev] })
	for table, rs := range rows {
		if err := s.ch.insert(r.Context(), table, rs); err != nil {
			s.log.Error("evidence write failed", "table", table, "err", err, "host_id", id.HostID)
			if b.ID != "" {
				s.cache.rdb.Del(context.WithoutCancel(r.Context()), "pg:evidence:batch:"+id.TenantID+":"+b.ID)
			}
			httpError(w, http.StatusServiceUnavailable, "evidence store unavailable")
			return
		}
	}
	stats, _ := json.Marshal(map[string]any{"at": time.Now().UTC().Unix(), "host_id": id.HostID, "stats": b.Stats})
	s.cache.rdb.Set(r.Context(), evidenceStatsKey+id.TenantID, stats, 7*24*time.Hour)
	writeJSON(w, http.StatusOK, proto.EvidenceResponse{Accepted: len(b.Logs) + len(b.Flows) + len(b.FDB)})
}

// buildEvidenceRows turns a batch into rows per ClickHouse table.
func buildEvidenceRows(tenantID, expires string, b proto.EvidenceBatch, devByIP map[netip.Addr]string, polled func(string) bool) map[string][]map[string]any {
	out := map[string][]map[string]any{}
	add := func(table string, row map[string]any) {
		row["tenant_id"], row["expires"] = tenantID, expires
		out[table] = append(out[table], row)
	}
	for _, l := range b.Logs {
		src := addr(l.Src)
		dev := devByIP[src.Unmap()]
		p := parseLog(l.Line, l.At)
		kv := p.KV
		if kv != nil && kv["type"] == "traffic" {
			add("fw_sessions", map[string]any{
				"received_at": chTime(l.At), "event_time": chTime(p.EventTime), "source": ip6(src), "device_id": dev,
				"devname": kv["devname"], "logid": kv["logid"], "subtype": kv["subtype"], "action": kv["action"],
				"policy_id": u64(kv["policyid"]), "proto": u64(kv["proto"]), "service": kv["service"], "app": kv["app"],
				"src_ip": ip6(addr(kv["srcip"])), "src_port": u64(kv["srcport"]), "src_intf": kv["srcintf"], "src_mac": strings.ToLower(kv["srcmac"]),
				"dst_ip": ip6(addr(kv["dstip"])), "dst_port": u64(kv["dstport"]), "dst_intf": kv["dstintf"],
				"nat_src_ip": ip6(addr(kv["transip"])), "nat_src_port": u64(kv["transport"]),
				"nat_dst_ip": ip6(addr(kv["tranip"])), "nat_dst_port": u64(kv["tranport"]),
				"user": kv["user"], "session_id": u64(kv["sessionid"]), "duration": u64(kv["duration"]),
				"sent_bytes": u64(kv["sentbyte"]), "rcvd_bytes": u64(kv["rcvdbyte"]), "raw": l.Line,
			})
			continue
		}
		ips := make([]string, 0, len(p.IPs))
		for _, a := range p.IPs {
			ips = append(ips, ip6(a))
		}
		parsed := 0
		if p.Parsed {
			parsed = 1
		}
		add("syslog", map[string]any{
			"received_at": chTime(l.At), "event_time": chTime(p.EventTime), "source": ip6(src), "device_id": dev,
			"facility": p.Facility, "severity": p.Severity, "hostname": p.Hostname, "program": p.Program,
			"message": p.Message, "raw": l.Line, "ips": ips, "parsed": parsed,
		})
		if kv != nil {
			if ip, user, action, ok := identityEvent(kv); ok {
				add("ip_users", map[string]any{
					"received_at": chTime(l.At), "event_time": chTime(p.EventTime), "ip": ip6(addr(ip)), "user": user,
					"source": ip6(src), "device_id": dev, "action": action, "raw": l.Line,
				})
			}
		}
	}
	for _, f := range b.Flows {
		exp := addr(f.Exporter)
		start, end := f.Start, f.End
		if start.IsZero() {
			start = f.At
		}
		if end.IsZero() {
			end = f.At
		}
		add("flows", map[string]any{
			"received_at": chTime(f.At), "flow_start": chTime(start), "flow_end": chTime(end), "exporter": ip6(exp),
			"device_id": devByIP[exp.Unmap()], "flow_type": f.Type, "sampling": f.Sampling, "proto": f.Proto,
			"src_ip": ip6(addr(f.SrcIP)), "dst_ip": ip6(addr(f.DstIP)), "src_port": f.SrcPort, "dst_port": f.DstPort,
			"in_if": f.InIf, "out_if": f.OutIf, "bytes": f.Bytes, "packets": f.Packets, "tcp_flags": f.TCPFlags,
			"vlan": f.VLAN, "src_mac": f.SrcMAC, "dst_mac": f.DstMAC,
		})
	}
	for _, e := range b.FDB {
		if !polled(e.DeviceID) {
			continue // only devices this collector polls
		}
		add("mac_table", map[string]any{
			"received_at": chTime(e.At), "device_id": e.DeviceID, "port": e.Port, "if_index": e.IfIndex,
			"vlan": e.VLAN, "mac": strings.ToLower(e.MAC), "ip": ip6(addr(e.IP)), "source": e.Source,
		})
	}
	return out
}
