package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The alerter connects as pulsegrid_service (BYPASSRLS): it evaluates every
// tenant's rules. Every write takes tenant_id from the rule being evaluated,
// and every query that touches hosts or channels filters on that tenant, so
// one tenant's rule can never reach another tenant's hosts or contacts.

type rule struct {
	ID              string
	TenantID        string
	Name            string
	Kind            string
	Metric          string
	Operator        string
	Threshold       float64
	DurationSeconds int
	HostID          *string
	Tag             *string
	Target          string // process or service name, for process_down / service_down
}

type host struct {
	ID        string
	Hostname  string
	CreatedAt time.Time
	Tags      []string
	DependsOn *string
}

type channel struct {
	ID     string
	Type   string
	Target string
}

type storedState struct {
	alertState
	IncidentID *string
}

type store struct {
	pool *pgxpool.Pool
}

// rules returns enabled rules of active tenants in this worker's partition.
// Partitioning by tenant keeps one tenant's rules on one worker.
func (s *store) rules(ctx context.Context, partition, partitions int) ([]rule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.id, r.tenant_id, r.name, r.kind, coalesce(r.metric, ''), coalesce(r.operator, ''),
		       coalesce(r.threshold, 0), r.duration_seconds, r.host_id, r.tag, coalesce(r.target, '')
		  FROM alert_rules r JOIN tenants t ON t.id = r.tenant_id
		 WHERE r.enabled AND t.status = 'active'
		   AND abs(hashtext(r.tenant_id::text)) % $2 = $1`, partition, partitions)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (rule, error) {
		var r rule
		err := row.Scan(&r.ID, &r.TenantID, &r.Name, &r.Kind, &r.Metric, &r.Operator,
			&r.Threshold, &r.DurationSeconds, &r.HostID, &r.Tag, &r.Target)
		return r, err
	})
}

// hosts returns the hosts a rule covers: all of the tenant's, one, or those
// with the rule's tag.
func (s *store) hosts(ctx context.Context, r rule) ([]host, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, hostname, created_at, tags, depends_on_host_id FROM hosts
		 WHERE tenant_id = $1 AND revoked_at IS NULL AND ($2::uuid IS NULL OR id = $2)
		   AND ($3::text IS NULL OR $3 = ANY (tags))`,
		r.TenantID, r.HostID, r.Tag)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanHost)
}

func scanHost(row pgx.CollectableRow) (host, error) {
	var h host
	err := row.Scan(&h.ID, &h.Hostname, &h.CreatedAt, &h.Tags, &h.DependsOn)
	return h, err
}

func (s *store) host(ctx context.Context, tenantID, hostID string) (host, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, hostname, created_at, tags, depends_on_host_id FROM hosts
		 WHERE tenant_id = $1 AND id = $2`, tenantID, hostID)
	if err != nil {
		return host{}, err
	}
	return pgx.CollectExactlyOneRow(rows, scanHost)
}

// maintenance returns the tenant's enabled maintenance windows.
func (s *store) maintenance(ctx context.Context, tenantID string) ([]window, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT host_id, tag, schedule, starts_at, ends_at, coalesce(weekdays, '{}'),
		       coalesce(to_char(start_time, 'HH24:MI'), ''), coalesce(duration_minutes, 0), timezone
		  FROM maintenance_windows WHERE tenant_id = $1 AND enabled`, tenantID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (window, error) {
		var w window
		err := row.Scan(&w.HostID, &w.Tag, &w.Schedule, &w.StartsAt, &w.EndsAt, &w.Weekdays,
			&w.StartTime, &w.DurationMinutes, &w.Timezone)
		return w, err
	})
}

func (s *store) states(ctx context.Context, ruleID string) (map[string]storedState, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT host_id, state, since, incident_id FROM alert_states WHERE rule_id = $1`, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]storedState{}
	for rows.Next() {
		var hostID string
		var st storedState
		if err := rows.Scan(&hostID, &st.State, &st.Since, &st.IncidentID); err != nil {
			return nil, err
		}
		out[hostID] = st
	}
	return out, rows.Err()
}

// channels: the rule's own verified channels, or the tenant's verified
// default channel when the rule names none.
func (s *store) channels(ctx context.Context, tx pgx.Tx, r rule) ([]channel, error) {
	rows, err := tx.Query(ctx, `
		SELECT c.id, c.type, c.target
		  FROM alert_rule_channels rc JOIN notification_channels c ON c.id = rc.channel_id
		 WHERE rc.rule_id = $1 AND c.tenant_id = $2 AND c.verified_at IS NOT NULL`, r.ID, r.TenantID)
	if err != nil {
		return nil, err
	}
	chans, err := pgx.CollectRows(rows, scanChannel)
	if err != nil || len(chans) > 0 {
		return chans, err
	}
	var linked bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM alert_rule_channels WHERE rule_id = $1)`, r.ID).Scan(&linked); err != nil {
		return nil, err
	}
	if linked {
		return nil, nil // channels chosen but none verified yet: send nothing
	}
	rows, err = tx.Query(ctx, `
		SELECT id, type, target FROM notification_channels
		 WHERE tenant_id = $1 AND is_default AND verified_at IS NOT NULL`, r.TenantID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanChannel)
}

func scanChannel(row pgx.CollectableRow) (channel, error) {
	var c channel
	err := row.Scan(&c.ID, &c.Type, &c.Target)
	return c, err
}

// apply persists one transition, and opens or resolves the incident (plus
// its notifications) in the same transaction, so state and incidents can't
// disagree after a crash.
//
// quiet resolves without notifying: the host is in maintenance or behind a
// host that's down, and nobody wants a "recovered" for an alert they never got.
func (s *store) apply(
	ctx context.Context, r rule, h host, prev storedState, next alertState, act action, value float64,
	quiet bool, msg func(kind string, incidentID string) message,
) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	incidentID := prev.IncidentID
	var kind string
	switch act {
	case actionOpen:
		var id string
		m := msg("alert_firing", "")
		err = tx.QueryRow(ctx, `
			INSERT INTO incidents (tenant_id, rule_id, host_id, summary, rule_name, hostname, value)
			VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
			r.TenantID, r.ID, h.ID, m.Event["summary"], r.Name, h.Hostname, value).Scan(&id)
		if err != nil {
			return err
		}
		incidentID, kind = &id, "alert_firing"
	case actionResolve:
		if incidentID != nil {
			_, err = tx.Exec(ctx, `
				UPDATE incidents SET status = 'resolved', resolved_at = now()
				 WHERE id = $1 AND tenant_id = $2`, *incidentID, r.TenantID)
			if err != nil {
				return err
			}
		}
		kind = "alert_resolved"
	}

	if kind != "" && incidentID != nil && !quiet {
		chans, err := s.channels(ctx, tx, r)
		if err != nil {
			return err
		}
		m := msg(kind, *incidentID)
		payload, err := json.Marshal(m)
		if err != nil {
			return err
		}
		if err := enqueue(ctx, tx, r.TenantID, chans, *incidentID, kind, payload); err != nil {
			return err
		}
	}
	if act == actionResolve {
		incidentID = nil
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO alert_states (rule_id, host_id, tenant_id, state, since, last_value, incident_id, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now())
		ON CONFLICT (rule_id, host_id) DO UPDATE SET
		    state = EXCLUDED.state, since = EXCLUDED.since, last_value = EXCLUDED.last_value,
		    incident_id = EXCLUDED.incident_id, updated_at = now()`,
		r.ID, h.ID, r.TenantID, next.State, next.Since, value, incidentID)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func enqueue(ctx context.Context, tx pgx.Tx, tenantID string, chans []channel, incidentID, kind string, payload []byte) error {
	for _, c := range chans {
		_, err := tx.Exec(ctx, `
			INSERT INTO outbound_messages (tenant_id, channel_id, incident_id, kind, payload)
			VALUES ($1, $2, $3, $4, $5)`, tenantID, c.ID, incidentID, kind, payload)
		if err != nil {
			return err
		}
	}
	return nil
}

// ── Escalation ───────────────────────────────────────────────────────────────

// escalation is an open, unacknowledged incident whose next escalation step
// is due.
type escalation struct {
	IncidentID string
	TenantID   string
	HostID     *string
	Summary    string
	RuleName   string
	Hostname   string
	Value      *float64
	OpenedAt   time.Time
	Level      int // the step about to run (0-based position)
	Steps      int // how many steps the rule has
	ChannelIDs []string
}

// dueEscalations finds incidents in this partition whose next step's delay
// (counted from when the incident opened) has passed.
func (s *store) dueEscalations(ctx context.Context, partition, partitions int) ([]escalation, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT i.id, i.tenant_id, i.host_id, i.summary, i.rule_name, i.hostname, i.value,
		       i.opened_at, i.escalation_level,
		       (SELECT count(*) FROM alert_escalation_steps a WHERE a.rule_id = i.rule_id),
		       st.channel_ids::text[]
		  FROM incidents i
		  JOIN tenants t ON t.id = i.tenant_id AND t.status = 'active'
		  JOIN alert_rules r ON r.id = i.rule_id AND r.tenant_id = i.tenant_id AND r.enabled
		  JOIN alert_escalation_steps st
		       ON st.rule_id = r.id AND st.tenant_id = i.tenant_id AND st.position = i.escalation_level
		 WHERE i.status = 'open' AND i.acknowledged_at IS NULL
		   AND i.opened_at + make_interval(secs => st.delay_seconds) <= now()
		   AND abs(hashtext(i.tenant_id::text)) % $2 = $1`, partition, partitions)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (escalation, error) {
		var e escalation
		err := row.Scan(&e.IncidentID, &e.TenantID, &e.HostID, &e.Summary, &e.RuleName, &e.Hostname,
			&e.Value, &e.OpenedAt, &e.Level, &e.Steps, &e.ChannelIDs)
		return e, err
	})
}

// escalate notifies a step's verified channels and moves the incident to the
// next step, in one transaction. The level check makes a second evaluator
// (or a retry) a no-op instead of a duplicate page.
func (s *store) escalate(ctx context.Context, e escalation, payload []byte) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `
		UPDATE incidents SET escalation_level = escalation_level + 1
		 WHERE id = $1 AND tenant_id = $2 AND escalation_level = $3
		   AND status = 'open' AND acknowledged_at IS NULL`, e.IncidentID, e.TenantID, e.Level)
	if err != nil || tag.RowsAffected() == 0 {
		return false, err
	}
	rows, err := tx.Query(ctx, `
		SELECT id, type, target FROM notification_channels
		 WHERE tenant_id = $1 AND id = ANY ($2::uuid[]) AND verified_at IS NOT NULL`, e.TenantID, e.ChannelIDs)
	if err != nil {
		return false, err
	}
	chans, err := pgx.CollectRows(rows, scanChannel)
	if err != nil {
		return false, err
	}
	if err := enqueue(ctx, tx, e.TenantID, chans, e.IncidentID, "alert_escalation", payload); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// ── Outbox ───────────────────────────────────────────────────────────────────

type outboxItem struct {
	ID       string
	Kind     string
	Payload  message
	Attempts int
	Channel  channel
}

const leaseDuration = 2 * time.Minute

// claim leases pending messages by pushing next_attempt_at forward, so a
// crashed sender's messages come back on their own and two dispatchers never
// send the same one.
func (s *store) claim(ctx context.Context, limit int) ([]outboxItem, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE outbound_messages m SET next_attempt_at = now() + make_interval(secs => $2)
		  FROM notification_channels c
		 WHERE c.id = m.channel_id AND c.tenant_id = m.tenant_id
		   AND m.id IN (
		       SELECT id FROM outbound_messages
		        WHERE status = 'pending' AND next_attempt_at <= now()
		        ORDER BY next_attempt_at
		        LIMIT $1
		          FOR UPDATE SKIP LOCKED)
		RETURNING m.id, m.kind, m.payload, m.attempts, c.id, c.type, c.target`,
		limit, leaseDuration.Seconds())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (outboxItem, error) {
		var it outboxItem
		var payload []byte
		err := row.Scan(&it.ID, &it.Kind, &payload, &it.Attempts, &it.Channel.ID, &it.Channel.Type, &it.Channel.Target)
		if err == nil {
			err = json.Unmarshal(payload, &it.Payload)
		}
		return it, err
	})
}

func (s *store) markSent(ctx context.Context, id string) error {
	// Verification codes are only needed until they're delivered.
	_, err := s.pool.Exec(ctx, `
		UPDATE outbound_messages
		   SET status = 'sent', sent_at = now(), attempts = attempts + 1, last_error = NULL,
		       payload = payload - 'code'
		 WHERE id = $1`, id)
	return err
}

func (s *store) markFailed(ctx context.Context, id string, sendErr error, retryIn time.Duration) error {
	status := "pending"
	var permanent *permanentError
	if retryIn <= 0 || errors.As(sendErr, &permanent) {
		status, retryIn = "failed", 0
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE outbound_messages
		   SET status = $2, attempts = attempts + 1, last_error = left($3, 500),
		       next_attempt_at = now() + make_interval(secs => $4)
		 WHERE id = $1`, id, status, sendErr.Error(), retryIn.Seconds())
	return err
}
