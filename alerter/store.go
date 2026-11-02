package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The alerter connects as sentinel_service (BYPASSRLS): it evaluates every
// tenant's rules. Every write takes tenant_id from the rule being evaluated,
// and every query that touches hosts or channels filters on that tenant, so
// one tenant's rule can never reach another tenant's hosts or contacts.

type rule struct {
	ID                string
	TenantID          string
	Name              string
	Kind              string
	Metric            string
	Operator          string
	Threshold         float64
	DurationSeconds   int
	HostID            *string
	Tag               *string
	Target            string // process, service, plugin, container, check id or custom metric
	Aggregation       string
	WindowSeconds     int
	RecoveryThreshold *float64
	Severity          string
	ActionName        *string
	Labels            map[string]string
	Description       string
	Check             *checkInfo // kind check: the check, if it still exists
	LogsAccount       int64      // the tenant's VictoriaLogs AccountID (kind logs)
}

type checkInfo struct {
	ID         string
	Name       string
	Type       string
	Mode       string // file checks: params.mode
	OnProbes   bool
	HostID     *string
	Tag        *string
	MinFailing int
	CreatedAt  time.Time
}

// host is what a rule is evaluated for. For a probe-run uptime check it's
// the check itself (IsCheck): ID and Hostname are the check's id and name.
type host struct {
	ID        string
	Hostname  string
	CreatedAt time.Time
	Tags      []string
	DependsOn *string
	IsCheck   bool
	Allowed   []string // actions the host's allow-list permits
}

type channel struct {
	ID          string
	Type        string
	Target      string
	Config      map[string]string
	MinSeverity string
	Quiet       *quietHours // nil: no quiet hours
}

var severityRank = map[string]int{"info": 0, "warning": 1, "critical": 2}

// wants reports whether a contact receives alerts of this severity.
func (c channel) wants(severity string) bool {
	return severityRank[severity] >= severityRank[c.MinSeverity]
}

type storedState struct {
	alertState
	IncidentID *string
	Flips      []time.Time // recent openings, for flapping detection
}

type store struct {
	pool *pgxpool.Pool
}

// rules returns enabled rules of active tenants in this worker's partition.
// Partitioning by tenant keeps one tenant's rules on one worker.
func (s *store) rules(ctx context.Context, partition, partitions int) ([]rule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.id, r.tenant_id, r.name, r.kind, coalesce(r.metric, ''), coalesce(r.operator, ''),
		       coalesce(r.threshold, 0), r.duration_seconds, r.host_id, r.tag, coalesce(r.target, ''),
		       r.aggregation, r.window_seconds, r.recovery_threshold, r.severity, r.action_name,
		       r.labels, coalesce(r.description, ''),
		       c.id, coalesce(c.name, ''), coalesce(c.type, ''), coalesce(c.params->>'mode', ''),
		       coalesce(c.on_probes, false), c.host_id, c.tag,
		       coalesce(c.min_failing, 1), coalesce(c.created_at, now()), t.logs_account_id
		  FROM alert_rules r
		  JOIN tenants t ON t.id = r.tenant_id
		  LEFT JOIN checks c ON r.kind = 'check' AND c.id::text = r.target
		                    AND c.tenant_id = r.tenant_id AND c.enabled
		 WHERE r.enabled AND t.status = 'active'
		   AND abs(hashtext(r.tenant_id::text)) % $2 = $1`, partition, partitions)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (rule, error) {
		var r rule
		var c checkInfo
		var checkID *string
		err := row.Scan(&r.ID, &r.TenantID, &r.Name, &r.Kind, &r.Metric, &r.Operator,
			&r.Threshold, &r.DurationSeconds, &r.HostID, &r.Tag, &r.Target,
			&r.Aggregation, &r.WindowSeconds, &r.RecoveryThreshold, &r.Severity, &r.ActionName,
			&r.Labels, &r.Description,
			&checkID, &c.Name, &c.Type, &c.Mode, &c.OnProbes, &c.HostID, &c.Tag, &c.MinFailing, &c.CreatedAt,
			&r.LogsAccount)
		if checkID != nil {
			c.ID = *checkID
			r.Check = &c
		}
		return r, err
	})
}

// hosts returns the hosts a rule covers: all of the tenant's, one, or those
// with the rule's tag. Paused servers are left out: nothing about them is
// evaluated or opened until they're resumed.
func (s *store) hosts(ctx context.Context, r rule) ([]host, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, hostname, created_at, tags, depends_on_host_id, allowed_actions FROM hosts
		 WHERE tenant_id = $1 AND revoked_at IS NULL AND paused_at IS NULL AND ($2::uuid IS NULL OR id = $2)
		   AND ($3::text IS NULL OR $3 = ANY (tags))`,
		r.TenantID, r.HostID, r.Tag)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanHost)
}

func scanHost(row pgx.CollectableRow) (host, error) {
	var h host
	err := row.Scan(&h.ID, &h.Hostname, &h.CreatedAt, &h.Tags, &h.DependsOn, &h.Allowed)
	return h, err
}

func (s *store) host(ctx context.Context, tenantID, hostID string) (host, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, hostname, created_at, tags, depends_on_host_id, allowed_actions FROM hosts
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
		`SELECT subject_id, state, since, incident_id, flips FROM alert_states WHERE rule_id = $1`, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]storedState{}
	for rows.Next() {
		var hostID string
		var st storedState
		if err := rows.Scan(&hostID, &st.State, &st.Since, &st.IncidentID, &st.Flips); err != nil {
			return nil, err
		}
		out[hostID] = st
	}
	return out, rows.Err()
}

// channels: the rule's own verified channels plus whoever is on call in its
// schedules, or the tenant's verified default channel when it names neither.
// Also returns who was on call, for the incident timeline.
func (s *store) channels(ctx context.Context, tx pgx.Tx, r rule) ([]channel, []string, error) {
	var scheduleIDs []string
	if err := tx.QueryRow(ctx, `SELECT schedule_ids::text[] FROM alert_rules WHERE id = $1`, r.ID).Scan(&scheduleIDs); err != nil {
		return nil, nil, err
	}
	if len(scheduleIDs) == 0 {
		chans, err := s.ruleChannels(ctx, tx, r)
		return chans, nil, err
	}
	onCall, who, err := onCallChannels(ctx, tx, r.TenantID, scheduleIDs, time.Now())
	if err != nil {
		return nil, nil, err
	}
	rows, err := tx.Query(ctx, `
		SELECT c.id, c.type, c.target, c.config, c.min_severity, c.quiet_hours
		  FROM alert_rule_channels rc JOIN notification_channels c ON c.id = rc.channel_id
		 WHERE rc.rule_id = $1 AND c.tenant_id = $2 AND c.verified_at IS NOT NULL`, r.ID, r.TenantID)
	if err != nil {
		return nil, nil, err
	}
	own, err := pgx.CollectRows(rows, scanChannel)
	if err != nil {
		return nil, nil, err
	}
	return mergeChannels(own, onCall), who, nil
}

func (s *store) ruleChannels(ctx context.Context, tx pgx.Tx, r rule) ([]channel, error) {
	rows, err := tx.Query(ctx, `
		SELECT c.id, c.type, c.target, c.config, c.min_severity, c.quiet_hours
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
	// No contacts chosen: the default one and the account's team members.
	rows, err = tx.Query(ctx, `
		SELECT id, type, target, config, min_severity, quiet_hours FROM notification_channels
		 WHERE tenant_id = $1 AND (is_default OR source = 'team') AND verified_at IS NOT NULL`, r.TenantID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanChannel)
}

func scanChannel(row pgx.CollectableRow) (channel, error) {
	var c channel
	err := row.Scan(&c.ID, &c.Type, &c.Target, &c.Config, &c.MinSeverity, &c.Quiet)
	return c, err
}

// Flapping: an alert that opened this many times within flapWindow keeps
// its incidents but stops notifying until it settles.
const (
	flapWindow    = time.Hour
	flapThreshold = 4
)

// apply persists one transition, and opens or resolves the incident (plus
// its notifications, timeline and any automatic action) in the same
// transaction, so state and incidents can't disagree after a crash.
//
// quiet resolves without notifying: the host is in maintenance or behind a
// host that's down, and nobody wants a "recovered" for an alert they never got.
func (s *store) apply(
	ctx context.Context, r rule, h host, prev storedState, next alertState, act action, o observation,
	quiet bool, msg func(kind string, incidentID string) message,
) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var hostID, checkID *string
	if h.IsCheck {
		checkID = &h.ID
	} else {
		hostID = &h.ID
		if r.Check != nil {
			checkID = &r.Check.ID
		}
	}
	incidentID := prev.IncidentID
	flips := recentFlips(prev.Flips, time.Now())
	var kind string
	flapping := false
	switch act {
	case actionOpen:
		flips = append(flips, time.Now())
		flapping = len(flips) >= flapThreshold
		var id string
		m := msg("alert_firing", "")
		err = tx.QueryRow(ctx, `
			INSERT INTO incidents (tenant_id, rule_id, host_id, check_id, summary, rule_name, hostname,
			                       value, severity, detail, flapping)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, nullif($10, ''), $11) RETURNING id`,
			r.TenantID, r.ID, hostID, checkID, m.Event["summary"], r.Name, h.Hostname, o.Value,
			r.Severity, o.Detail, flapping).Scan(&id)
		if err != nil {
			return err
		}
		incidentID, kind = &id, "alert_firing"
		text := fmt.Sprint(m.Event["condition"])
		if o.Detail != "" {
			text += " — " + o.Detail
		}
		if err := addEvent(ctx, tx, r.TenantID, id, "opened", text, "alerter"); err != nil {
			return err
		}
		if flapping {
			if err := addEvent(ctx, tx, r.TenantID, id, "flapping",
				fmt.Sprintf("Opened %d times in the last hour: notifications are paused until it settles", len(flips)),
				"alerter"); err != nil {
				return err
			}
		}
		if err := s.queueRuleAction(ctx, tx, r, h, id); err != nil {
			return err
		}
	case actionResolve:
		if incidentID != nil {
			_, err = tx.Exec(ctx, `
				UPDATE incidents SET status = 'resolved', resolved_at = now(), resolved_by = 'alerter'
				 WHERE id = $1 AND tenant_id = $2 AND status = 'open'`, *incidentID, r.TenantID)
			if err != nil {
				return err
			}
			text := "Recovered"
			if quiet {
				text = "Recovered during maintenance or while a dependency was down (not notified)"
			}
			if err := addEvent(ctx, tx, r.TenantID, *incidentID, "resolved", text, "alerter"); err != nil {
				return err
			}
			// Merged into another incident: that one carries the story, so
			// the recovery goes on its timeline and nobody gets a separate
			// "resolved" for an alert they handled as part of it.
			var mergedInto *string
			tx.QueryRow(ctx, `SELECT merged_into FROM incidents WHERE id = $1`, *incidentID).Scan(&mergedInto)
			if mergedInto != nil {
				quiet = true
				if err := addEvent(ctx, tx, r.TenantID, *mergedInto, "note",
					"Merged alert recovered: "+r.Name+" on "+h.Hostname, "alerter"); err != nil {
					return err
				}
			}
			// A flapping incident never notified that it opened, so it
			// doesn't notify that it closed either.
			var wasFlapping bool
			tx.QueryRow(ctx, `SELECT flapping FROM incidents WHERE id = $1`, *incidentID).Scan(&wasFlapping)
			quiet = quiet || (wasFlapping && len(flips) > flapThreshold)
		}
		kind = "alert_resolved"
	}

	// While flapping, only the opening that crossed the threshold notifies.
	if flapping && len(flips) > flapThreshold {
		quiet = true
	}
	if kind != "" && incidentID != nil && !quiet {
		chans, onCallNames, err := s.channels(ctx, tx, r)
		if err != nil {
			return err
		}
		var wanted []channel
		for _, c := range chans {
			if c.wants(r.Severity) {
				wanted = append(wanted, c)
			}
		}
		m := msg(kind, *incidentID)
		if flapping {
			m.Subject += " (flapping: further alerts paused)"
		}
		payload, err := json.Marshal(m)
		if err != nil {
			return err
		}
		var delay time.Duration
		if r.Kind == "host_down" && kind == "alert_firing" {
			delay = hostDownGather
		}
		held, err := enqueue(ctx, tx, r.TenantID, wanted, *incidentID, kind, r.Severity, payload, delay)
		if err != nil {
			return err
		}
		if len(wanted) > 0 {
			text := "Notified " + describeChannels(wanted)
			if len(onCallNames) > 0 {
				text += " (on call: " + joinNames(onCallNames) + ")"
			}
			if held > 0 {
				text += fmt.Sprintf("; %d held for quiet hours", held)
			}
			if err := addEvent(ctx, tx, r.TenantID, *incidentID, "notified", text, "alerter"); err != nil {
				return err
			}
		} else if len(onCallNames) == 0 && kind == "alert_firing" {
			if err := addEvent(ctx, tx, r.TenantID, *incidentID, "notified", "Nobody was notified: no verified contact and nobody on call", "alerter"); err != nil {
				return err
			}
		}
	}
	if act == actionResolve {
		incidentID = nil
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO alert_states (rule_id, subject_id, host_id, check_id, tenant_id, state, since,
		                          last_value, incident_id, flips, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())
		ON CONFLICT (rule_id, subject_id) DO UPDATE SET
		    state = EXCLUDED.state, since = EXCLUDED.since, last_value = EXCLUDED.last_value,
		    incident_id = EXCLUDED.incident_id, flips = EXCLUDED.flips, updated_at = now()`,
		r.ID, h.ID, hostID, checkIDIfSubject(h), r.TenantID, next.State, next.Since, o.Value, incidentID, flips)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func checkIDIfSubject(h host) *string {
	if h.IsCheck {
		return &h.ID
	}
	return nil
}

// recentFlips keeps the openings inside flapWindow. Never nil: pgx sends a
// nil slice as NULL, and the column is NOT NULL.
func recentFlips(flips []time.Time, now time.Time) []time.Time {
	out := []time.Time{}
	for _, f := range flips {
		if now.Sub(f) < flapWindow {
			out = append(out, f)
		}
	}
	return out
}

// queueRuleAction asks the host to run the rule's action, if the host's own
// allow-list permits it; otherwise it notes on the incident why it didn't.
func (s *store) queueRuleAction(ctx context.Context, tx pgx.Tx, r rule, h host, incidentID string) error {
	if r.ActionName == nil || h.IsCheck {
		return nil
	}
	if !slices.Contains(h.Allowed, *r.ActionName) {
		return addEvent(ctx, tx, r.TenantID, incidentID, "action",
			fmt.Sprintf("Action %s not run: this server doesn't allow it (sentinel-agent allow-action %s -- <command>)",
				*r.ActionName, *r.ActionName), "alerter")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO host_actions (tenant_id, host_id, name, requested_by, incident_id)
		VALUES ($1, $2, $3, $4, $5)`, r.TenantID, h.ID, *r.ActionName, "rule: "+r.Name, incidentID); err != nil {
		return err
	}
	return addEvent(ctx, tx, r.TenantID, incidentID, "action", "Requested action "+*r.ActionName+" on "+h.Hostname, "alerter")
}

func addEvent(ctx context.Context, tx pgx.Tx, tenantID, incidentID, kind, message, actor string) error {
	message = cut(message, 5000)
	_, err := tx.Exec(ctx, `
		INSERT INTO incident_events (tenant_id, incident_id, kind, message, actor, created_at)
		VALUES ($1, $2, $3, $4, $5, clock_timestamp())`, tenantID, incidentID, kind, message, actor)
	return err
}

// describeChannels summarises contacts without exposing their addresses.
func describeChannels(chans []channel) string {
	if len(chans) == 0 {
		return "nobody (no verified contacts)"
	}
	count := map[string]int{}
	var order []string
	for _, c := range chans {
		if count[c.Type] == 0 {
			order = append(order, c.Type)
		}
		count[c.Type]++
	}
	var parts []string
	for _, t := range order {
		name := map[string]string{"email": "email", "push": "push notification", "webhook": "webhook"}[t]
		if name == "" {
			name = t
		}
		if count[t] > 1 {
			parts = append(parts, fmt.Sprintf("%d × %s", count[t], name))
		} else {
			parts = append(parts, name)
		}
	}
	return strings.Join(parts, ", ")
}

// hostDownGather holds a "not reporting" alert briefly before it goes out:
// a server that's back by then sends nothing (skipBlips), and servers that
// drop together go out as one message per contact (groupHostDown).
const hostDownGather = 60 * time.Second

// enqueue queues one message per contact, due after delay. A contact in its
// quiet hours gets it when they end (next_attempt_at, held_until); returns
// how many were held.
func enqueue(ctx context.Context, tx pgx.Tx, tenantID string, chans []channel, incidentID, kind, severity string, payload []byte, delay time.Duration) (int, error) {
	held := 0
	now := time.Now()
	for _, c := range chans {
		var heldUntil *time.Time
		if t := c.Quiet.quietUntil(severity, now); !t.IsZero() {
			heldUntil = &t
			held++
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO outbound_messages (tenant_id, channel_id, incident_id, kind, payload, held_until, next_attempt_at)
			VALUES ($1, $2, $3, $4, $5, $6, coalesce($6, now() + make_interval(secs => $7)))`,
			tenantID, c.ID, incidentID, kind, payload, heldUntil, delay.Seconds())
		if err != nil {
			return held, err
		}
	}
	return held, nil
}

// ── Escalation ───────────────────────────────────────────────────────────────

// escalation is an open, unacknowledged incident whose next escalation step
// is due.
type escalation struct {
	IncidentID  string
	TenantID    string
	HostID      *string
	Summary     string
	RuleName    string
	Hostname    string
	Value       *float64
	OpenedAt    time.Time
	Level       int // the step about to run (0-based position)
	Steps       int // how many steps the rule has
	ChannelIDs  []string
	ScheduleIDs []string
	Severity    string
}

// dueEscalations finds incidents in this partition whose next step's delay
// (counted from when the incident opened) has passed. A snoozed incident
// waits; when the snooze ends, any overdue step goes out at once.
func (s *store) dueEscalations(ctx context.Context, partition, partitions int) ([]escalation, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT i.id, i.tenant_id, i.host_id, i.summary, i.rule_name, i.hostname, i.value,
		       i.opened_at, i.escalation_level,
		       (SELECT count(*) FROM alert_escalation_steps a WHERE a.rule_id = i.rule_id),
		       st.channel_ids::text[], st.schedule_ids::text[], i.severity
		  FROM incidents i
		  JOIN tenants t ON t.id = i.tenant_id AND t.status = 'active'
		  JOIN alert_rules r ON r.id = i.rule_id AND r.tenant_id = i.tenant_id AND r.enabled
		  JOIN alert_escalation_steps st
		       ON st.rule_id = r.id AND st.tenant_id = i.tenant_id AND st.position = i.escalation_level
		 WHERE i.status = 'open' AND i.acknowledged_at IS NULL
		   AND (i.snoozed_until IS NULL OR i.snoozed_until <= now())
		   AND i.opened_at + make_interval(secs => st.delay_seconds) <= now()
		   AND abs(hashtext(i.tenant_id::text)) % $2 = $1`, partition, partitions)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (escalation, error) {
		var e escalation
		err := row.Scan(&e.IncidentID, &e.TenantID, &e.HostID, &e.Summary, &e.RuleName, &e.Hostname,
			&e.Value, &e.OpenedAt, &e.Level, &e.Steps, &e.ChannelIDs, &e.ScheduleIDs, &e.Severity)
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
		SELECT id, type, target, config, min_severity, quiet_hours FROM notification_channels
		 WHERE tenant_id = $1 AND id = ANY ($2::uuid[]) AND verified_at IS NOT NULL`, e.TenantID, e.ChannelIDs)
	if err != nil {
		return false, err
	}
	chans, err := pgx.CollectRows(rows, scanChannel)
	if err != nil {
		return false, err
	}
	onCall, who, err := onCallChannels(ctx, tx, e.TenantID, e.ScheduleIDs, time.Now())
	if err != nil {
		return false, err
	}
	chans = mergeChannels(chans, onCall)
	// Escalations are for when nobody answered: they go out even in quiet
	// hours, like critical alerts.
	if _, err := enqueue(ctx, tx, e.TenantID, chans, e.IncidentID, "alert_escalation", "critical", payload, 0); err != nil {
		return false, err
	}
	text := fmt.Sprintf("Escalated to step %d of %d: notified %s", e.Level+1, e.Steps, describeChannels(chans))
	if len(who) > 0 {
		text += " (on call: " + joinNames(who) + ")"
	}
	if err := addEvent(ctx, tx, e.TenantID, e.IncidentID, "escalated", text, "alerter"); err != nil {
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

// skipStaleHeld drops messages held for quiet hours whose incident resolved
// meanwhile: the contact wakes up to neither the alert nor its resolution.
func (s *store) skipStaleHeld(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE outbound_messages m
		   SET status = 'skipped', last_error = 'Resolved during quiet hours: not sent'
		  FROM incidents i
		 WHERE m.incident_id = i.id AND m.tenant_id = i.tenant_id
		   AND m.status = 'pending' AND m.held_until IS NOT NULL
		   AND m.next_attempt_at <= now() AND i.status = 'resolved'
		   AND (m.kind IN ('alert_firing', 'alert_escalation')
		        OR (m.kind = 'alert_resolved' AND EXISTS (
		            SELECT 1 FROM outbound_messages f
		             WHERE f.incident_id = m.incident_id AND f.channel_id = m.channel_id
		               AND f.kind = 'alert_firing' AND f.status IN ('skipped', 'pending')
		               AND f.held_until IS NOT NULL)))`)
	return tag.RowsAffected(), err
}

// skipBlips drops a "not reporting" alert whose server came back while it
// was being held (hostDownGather), and then its "reporting again". A firing
// message not yet claimed still has next_attempt_at within the hold: a
// claim pushes it past that, so one being sent right now is left alone.
func (s *store) skipBlips(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE outbound_messages m
		   SET status = 'skipped', last_error = $1
		  FROM incidents i
		 WHERE m.incident_id = i.id AND m.tenant_id = i.tenant_id
		   AND m.status = 'pending' AND m.kind = 'alert_firing' AND m.attempts = 0
		   AND m.held_until IS NULL AND m.payload->'event'->>'kind' = 'host_down'
		   AND m.next_attempt_at <= m.created_at + make_interval(secs => $2)
		   AND i.status = 'resolved'`, blipSkipped, hostDownGather.Seconds()+1)
	if err != nil {
		return 0, err
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE outbound_messages m
		   SET status = 'skipped', last_error = $1
		 WHERE m.status = 'pending' AND m.kind = 'alert_resolved'
		   AND EXISTS (SELECT 1 FROM outbound_messages f
		                WHERE f.incident_id = m.incident_id AND f.channel_id = m.channel_id
		                  AND f.kind = 'alert_firing' AND f.status = 'skipped' AND f.last_error = $1)`, blipSkipped)
	return tag.RowsAffected(), err
}

const blipSkipped = "Server was back before the alert went out: not sent"

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
		RETURNING m.id, m.kind, m.payload, m.attempts, c.id, c.type, c.target, c.config`,
		limit, leaseDuration.Seconds())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (outboxItem, error) {
		var it outboxItem
		var payload []byte
		err := row.Scan(&it.ID, &it.Kind, &payload, &it.Attempts, &it.Channel.ID, &it.Channel.Type,
			&it.Channel.Target, &it.Channel.Config)
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

// markUndeliverable stops sending to a contact whose server refused it
// until someone verifies it again.
func (s *store) markUndeliverable(ctx context.Context, id, reason string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE notification_channels
		   SET undeliverable_at = now(), undeliverable_reason = left($2, 300), verified_at = NULL
		 WHERE id = $1`, id, reason)
	return err
}

// deleteChannel removes a contact the provider says no longer exists.
func (s *store) deleteChannel(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM notification_channels WHERE id = $1 AND type = 'push'`, id)
	return err
}

// failingPlugins reads which plugins the host's agent last reported as
// failing, and why, so a plugin alert names them instead of "A plugin".
// target limits it to one plugin.
func (s *store) failingPlugins(ctx context.Context, hostID, target string) (names, detail string) {
	rows, err := s.pool.Query(ctx, `
		SELECT p->>'name', coalesce(p->>'error', '')
		FROM host_inventory i, jsonb_array_elements(coalesce(i.data->'plugins', '[]'::jsonb)) p
		WHERE i.host_id = $1 AND p->>'ok' = 'false' AND ($2 = '' OR p->>'name' = $2)
		ORDER BY 1`, hostID, target)
	if err != nil {
		return "", ""
	}
	defer rows.Close()
	var ns, ds []string
	for rows.Next() {
		var n, e string
		if rows.Scan(&n, &e) != nil {
			continue
		}
		if len(e) > 400 {
			e = cut(e, 400) + "…"
		}
		ns = append(ns, n)
		ds = append(ds, n+": "+e)
	}
	return strings.Join(ns, ", "), strings.Join(ds, "\n")
}

// openPluginNames recovers the plugin names a still-open plugin incident
// was opened with ("Plugin smart, ipmi is failing on ..."), so the recovery
// names them too.
func (s *store) openPluginNames(ctx context.Context, ruleID, hostID string) string {
	var summary string
	if s.pool.QueryRow(ctx, `
		SELECT summary FROM incidents WHERE rule_id = $1 AND host_id = $2 AND status = 'open'
		ORDER BY opened_at DESC LIMIT 1`, ruleID, hostID).Scan(&summary) != nil {
		return ""
	}
	rest, ok := strings.CutPrefix(summary, "Plugin ")
	if !ok {
		return ""
	}
	names, _, ok := strings.Cut(rest, " is failing on ")
	if !ok {
		return ""
	}
	return names
}

type accountEmail struct {
	ID, To, Kind, Subject, Text, HTML string
	Attempts                          int
}

// claimAccountEmails leases pending account emails the way claim() leases
// alerts. Links in them carry single-use tokens, so after a send the
// payload is cleared.
func (s *store) claimAccountEmails(ctx context.Context, limit int) ([]accountEmail, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE account_emails m SET next_attempt_at = now() + make_interval(secs => $2)
		 WHERE m.id IN (
		       SELECT id FROM account_emails
		        WHERE status = 'pending' AND next_attempt_at <= now()
		        ORDER BY next_attempt_at
		        LIMIT $1
		          FOR UPDATE SKIP LOCKED)
		RETURNING m.id, m.to_address, m.kind, m.payload->>'subject', m.payload->>'text',
		          COALESCE(m.payload->>'html', ''), m.attempts`,
		limit, leaseDuration.Seconds())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (accountEmail, error) {
		var m accountEmail
		err := r.Scan(&m.ID, &m.To, &m.Kind, &m.Subject, &m.Text, &m.HTML, &m.Attempts)
		return m, err
	})
}

func (s *store) markAccountEmailSent(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE account_emails
		   SET status = 'sent', sent_at = now(), attempts = attempts + 1, last_error = NULL,
		       payload = '{}'::jsonb
		 WHERE id = $1`, id)
	return err
}

func (s *store) markAccountEmailFailed(ctx context.Context, id string, sendErr error, retryIn time.Duration) error {
	status := "pending"
	var permanent *permanentError
	if retryIn <= 0 || errors.As(sendErr, &permanent) {
		status, retryIn = "failed", 0
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE account_emails
		   SET status = $2, attempts = attempts + 1, last_error = left($3, 500),
		       next_attempt_at = now() + make_interval(secs => $4)
		 WHERE id = $1`, id, status, sendErr.Error(), retryIn.Seconds())
	return err
}
