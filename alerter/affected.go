package main

// Affected hosts: when a host stops reporting, the hosts behind it (that
// depend on it, set by hand or worked out from the topology, or that it
// polls) usually go quiet too. Their own alerts are held back (silentParents),
// so the one alert that goes out names them instead: the cause and its
// reach in one message.

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

const maxAffectedNamed = 10

// behind lists the hosts whose chain of upstreams reaches hostID.
func (s *store) behind(ctx context.Context, tenantID, hostID string) ([]host, error) {
	rows, err := s.pool.Query(ctx, `
		WITH RECURSIVE behind(id, depth) AS (
		    SELECT h.id, 1 FROM hosts h
		     WHERE h.tenant_id = $1 AND h.revoked_at IS NULL AND h.id <> $2
		       AND coalesce(h.depends_on_host_id, h.poller_host_id) = $2
		    UNION
		    SELECT h.id, b.depth + 1 FROM hosts h JOIN behind b ON coalesce(h.depends_on_host_id, h.poller_host_id) = b.id
		     WHERE h.tenant_id = $1 AND h.revoked_at IS NULL AND h.id <> $2 AND b.depth < 16)
		SELECT DISTINCT h.id::text, h.hostname FROM behind b JOIN hosts h ON h.id = b.id
		 LIMIT 5000`, tenantID, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []host
	for rows.Next() {
		var h host
		if err := rows.Scan(&h.ID, &h.Hostname); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// affectedDetail names the hosts behind h that aren't reporting either.
func (e *evaluator) affectedDetail(ctx context.Context, tenantID string, h host) string {
	hosts, err := e.store.behind(ctx, tenantID, h.ID)
	if err != nil || len(hosts) == 0 {
		return ""
	}
	silent, err := e.silentHosts(ctx, hosts)
	if err != nil {
		return ""
	}
	var names []string
	for _, b := range hosts {
		if silent[b.ID] {
			names = append(names, b.Hostname)
		}
	}
	return affectedLine(names)
}

func affectedLine(names []string) string {
	total := len(names)
	if total == 0 {
		return ""
	}
	sort.Strings(names)
	more := ""
	if total > maxAffectedNamed {
		more = fmt.Sprintf(" and %d more", total-maxAffectedNamed)
		names = names[:maxAffectedNamed]
	}
	what := "hosts"
	if total == 1 {
		what = "host"
	}
	return fmt.Sprintf("Behind it, %d %s not reporting either: %s%s", total, what, strings.Join(names, ", "), more)
}
