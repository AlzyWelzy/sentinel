package main

// Site incidents. Many servers behind one public IP (shared NAT), or the
// devices one poller watches, go quiet together when the site's link fails.
// Each one's "not reporting" alert still goes out (grouped into one email
// per person by dispatch), but five or more within 15 minutes become one
// incident for the site: their incidents are merged into it, later ones at
// the same site join it while it's open, and it resolves (with one recovery
// message) only when every one of them reports again. Members' own
// recoveries are noted on it instead of notifying (merged incidents are
// quiet).

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	siteMinHosts = 5
	siteWindow   = 15 * time.Minute
)

type siteMember struct {
	IncidentID, TenantID, HostID, Hostname, RuleID, Severity string
	Key, Label                                               string
}

// siteCandidates are recent open "not reporting" incidents, with their site.
func (s *store) siteCandidates(ctx context.Context, partition, partitions int) ([]siteMember, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT i.id, i.tenant_id, i.host_id, i.hostname, i.rule_id, i.severity,
		       CASE WHEN h.kind = 'network' AND h.poller_host_id IS NOT NULL THEN 'poller:' || h.poller_host_id::text
		            WHEN coalesce(h.public_ip, '') <> '' THEN 'ip:' || h.public_ip END,
		       CASE WHEN h.kind = 'network' AND h.poller_host_id IS NOT NULL
		            THEN 'polled by ' || coalesce((SELECT p.hostname FROM hosts p WHERE p.id = h.poller_host_id), 'a poller')
		            ELSE 'behind ' || h.public_ip END
		  FROM incidents i
		  JOIN alert_rules r ON r.id = i.rule_id AND r.tenant_id = i.tenant_id AND r.kind = 'host_down'
		  JOIN hosts h ON h.id = i.host_id AND h.tenant_id = i.tenant_id
		 WHERE i.status = 'open' AND i.merged_into IS NULL AND i.site_key IS NULL
		   AND i.opened_at > now() - make_interval(secs => $3)
		   AND abs(hashtext(i.tenant_id::text)) % $2 = $1`, partition, partitions, siteWindow.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []siteMember
	for rows.Next() {
		var m siteMember
		var key, label *string
		if err := rows.Scan(&m.IncidentID, &m.TenantID, &m.HostID, &m.Hostname, &m.RuleID, &m.Severity, &key, &label); err != nil {
			return nil, err
		}
		if key == nil {
			continue
		}
		m.Key, m.Label = *key, deref(label)
		out = append(out, m)
	}
	return out, rows.Err()
}

// gatherSite merges members into the site's open incident, opening one when
// there are enough of them.
func (s *store) gatherSite(ctx context.Context, members []siteMember) (opened bool, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	first := members[0]
	var siteID string
	err = tx.QueryRow(ctx, `SELECT id FROM incidents WHERE tenant_id = $1 AND site_key = $2 AND status = 'open'
		ORDER BY opened_at LIMIT 1 FOR UPDATE`, first.TenantID, first.Key).Scan(&siteID)
	if err != nil && len(members) < siteMinHosts {
		return false, nil // no open site incident, and not enough to open one
	}
	sev := "warning"
	for _, m := range members {
		if m.Severity == "critical" {
			sev = "critical"
		}
	}
	if siteID == "" {
		summary := fmt.Sprintf("%d hosts %s stopped reporting", len(members), first.Label)
		if err := tx.QueryRow(ctx, `
			INSERT INTO incidents (tenant_id, rule_id, summary, rule_name, hostname, severity, detail, site_key)
			VALUES ($1, $2, $3, 'Site not reporting', $4, $5, $6, $7) RETURNING id`,
			first.TenantID, first.RuleID, summary, cut(first.Label, 200), sev,
			"Several hosts at one site went quiet together: usually the site's link or power, not each host.",
			first.Key).Scan(&siteID); err != nil {
			return false, err
		}
		opened = true
		if err := addEvent(ctx, tx, first.TenantID, siteID, "opened", summary, "alerter"); err != nil {
			return false, err
		}
	}
	var names []string
	for _, m := range members {
		tag, err := tx.Exec(ctx, `
			UPDATE incidents SET merged_into = $3, status = 'resolved', resolved_at = now(), resolved_by = 'site outage'
			 WHERE id = $1 AND tenant_id = $2 AND merged_into IS NULL AND status = 'open'`, m.IncidentID, m.TenantID, siteID)
		if err != nil {
			return false, err
		}
		if tag.RowsAffected() == 0 {
			continue
		}
		names = append(names, m.Hostname)
		if err := addEvent(ctx, tx, m.TenantID, m.IncidentID, "merged", "Part of a site outage: merged into the site's incident", "alerter"); err != nil {
			return false, err
		}
	}
	if len(names) > 0 {
		sort.Strings(names)
		if err := addEvent(ctx, tx, first.TenantID, siteID, "merged",
			fmt.Sprintf("Not reporting: %s", strings.Join(names, ", ")), "alerter"); err != nil {
			return false, err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE incidents SET severity = CASE WHEN $3 = 'critical' THEN 'critical' ELSE severity END,
			       summary = (SELECT count(*) FROM incidents c WHERE c.merged_into = $1) || ' hosts ' || hostname || ' stopped reporting'
			 WHERE id = $1 AND tenant_id = $2`, siteID, first.TenantID, sev); err != nil {
			return false, err
		}
	}
	return opened, tx.Commit(ctx)
}

type openSite struct {
	ID, TenantID, RuleID, Summary, Label, Severity, Timezone string
	OpenedAt                                                 time.Time
	Members                                                  []host
}

func (s *store) openSites(ctx context.Context, partition, partitions int) ([]openSite, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT i.id, i.tenant_id, coalesce(i.rule_id::text, ''), i.summary, i.hostname, i.severity, i.opened_at,
		       coalesce(t.digest_timezone, 'UTC'),
		       coalesce(array_agg(c.host_id::text) FILTER (WHERE c.host_id IS NOT NULL), '{}'),
		       coalesce(array_agg(h.hostname) FILTER (WHERE c.host_id IS NOT NULL), '{}')
		  FROM incidents i
		  JOIN tenants t ON t.id = i.tenant_id
		  LEFT JOIN incidents c ON c.merged_into = i.id AND c.tenant_id = i.tenant_id
		  LEFT JOIN hosts h ON h.id = c.host_id
		 WHERE i.site_key IS NOT NULL AND i.status = 'open'
		   AND abs(hashtext(i.tenant_id::text)) % $2 = $1
		 GROUP BY i.id, t.digest_timezone`, partition, partitions)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []openSite
	for rows.Next() {
		var o openSite
		var ids, names []string
		if err := rows.Scan(&o.ID, &o.TenantID, &o.RuleID, &o.Summary, &o.Label, &o.Severity, &o.OpenedAt, &o.Timezone, &ids, &names); err != nil {
			return nil, err
		}
		for i := range ids {
			o.Members = append(o.Members, host{ID: ids[i], Hostname: names[i]})
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// resolveSite closes a site incident whose hosts all report again, with one
// recovery message to the members' rule contacts.
func (s *store) resolveSite(ctx context.Context, o openSite, payload []byte) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE incidents SET status = 'resolved', resolved_at = now(), resolved_by = 'alerter'
		WHERE id = $1 AND tenant_id = $2 AND status = 'open'`, o.ID, o.TenantID)
	if err != nil || tag.RowsAffected() == 0 {
		return false, err
	}
	if err := addEvent(ctx, tx, o.TenantID, o.ID, "resolved", "Every host at the site is reporting again", "alerter"); err != nil {
		return false, err
	}
	if o.RuleID != "" {
		chans, _, err := s.channels(ctx, tx, rule{ID: o.RuleID, TenantID: o.TenantID})
		if err != nil {
			return false, err
		}
		var wanted []channel
		for _, c := range chans {
			if c.wants(o.Severity) {
				wanted = append(wanted, c)
			}
		}
		if _, err := enqueue(ctx, tx, o.TenantID, wanted, o.ID, "alert_resolved", o.Severity, payload, 0); err != nil {
			return false, err
		}
	}
	return true, tx.Commit(ctx)
}

func (e *evaluator) sitesAll(ctx context.Context, partition, partitions int) {
	cands, err := e.store.siteCandidates(ctx, partition, partitions)
	if err != nil {
		e.log.Error("loading site candidates", "err", err)
		return
	}
	groups := map[string][]siteMember{}
	for _, m := range cands {
		k := m.TenantID + "|" + m.Key
		groups[k] = append(groups[k], m)
	}
	for _, g := range groups {
		opened, err := e.store.gatherSite(ctx, g)
		if err != nil {
			e.log.Error("site incident", "tenant_id", g[0].TenantID, "err", err)
			continue
		}
		if opened {
			e.log.Info("site incident opened", "tenant_id", g[0].TenantID, "site", g[0].Label, "hosts", len(g))
		}
	}
	sites, err := e.store.openSites(ctx, partition, partitions)
	if err != nil {
		e.log.Error("loading site incidents", "err", err)
		return
	}
	for _, o := range sites {
		if len(o.Members) == 0 {
			continue
		}
		silent, err := e.silentHosts(ctx, o.Members)
		if err != nil {
			continue
		}
		anySilent := false
		for _, h := range o.Members {
			if silent[h.ID] {
				anySilent = true
				break
			}
		}
		if anySilent {
			continue
		}
		payload, err := json.Marshal(e.siteResolvedMessage(o, time.Now()))
		if err != nil {
			continue
		}
		if ok, err := e.store.resolveSite(ctx, o, payload); err != nil {
			e.log.Error("resolving a site incident", "incident_id", o.ID, "err", err)
		} else if ok {
			e.log.Info("site incident resolved", "incident_id", o.ID, "tenant_id", o.TenantID)
		}
	}
}

func (e *evaluator) siteResolvedMessage(o openSite, now time.Time) message {
	var names []string
	for _, h := range o.Members {
		names = append(names, h.Hostname)
	}
	sort.Strings(names)
	listed := names
	more := ""
	if len(listed) > 20 {
		more = fmt.Sprintf(" and %d more", len(listed)-20)
		listed = listed[:20]
	}
	lasted := now.Sub(o.OpenedAt).Round(time.Minute)
	subject := fmt.Sprintf("[Sentinel] RESOLVED: %d hosts %s are reporting again", len(names), o.Label)
	text := fmt.Sprintf("RESOLVED: every host %s is reporting again after %s.\n\nHosts: %s%s\nOpened: %s\n",
		o.Label, lasted, strings.Join(listed, ", "), more, localTime(o.OpenedAt, o.Timezone))
	text += e.links(o.ID, false)
	return message{
		Subject: subject,
		Text:    text,
		Event: map[string]any{
			"type":        "alert_resolved",
			"summary":     o.Summary,
			"incident_id": o.ID,
			"rule_name":   "Site not reporting",
			"hostname":    o.Label,
			"severity":    o.Severity,
			"condition":   fmt.Sprintf("Every host %s is reporting again (down %s).", o.Label, lasted),
			"opened_at":   o.OpenedAt.UTC().Format(time.RFC3339),
			"at":          now.UTC().Format(time.RFC3339),
			"timezone":    o.Timezone,
		},
	}
}
