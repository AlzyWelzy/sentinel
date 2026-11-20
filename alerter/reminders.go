package main

// Reminders: an incident still open and unacknowledged is sent again to the
// rule's contacts every reminder_minutes (the organisation's setting; 240 by
// default, 0 off). Acknowledging, snoozing, merging or maintenance stop
// them; a flapping incident (whose alerts are paused) gets none. Unlike
// escalations, reminders respect each contact's quiet hours.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type reminder struct {
	IncidentID, TenantID, RuleID     string
	HostID                           *string
	Summary, RuleName, Hostname, Sev string
	Detail                           *string
	OpenedAt                         time.Time
	Sent                             int
	Timezone                         string
}

func (s *store) dueReminders(ctx context.Context, partition, partitions int) ([]reminder, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT i.id, i.tenant_id, i.rule_id, i.host_id, i.summary, i.rule_name, i.hostname, i.severity,
		       i.detail, i.opened_at, i.reminders_sent, coalesce(t.digest_timezone, 'UTC')
		  FROM incidents i
		  JOIN tenants t ON t.id = i.tenant_id AND t.status = 'active' AND t.reminder_minutes > 0
		  JOIN alert_rules r ON r.id = i.rule_id AND r.tenant_id = i.tenant_id AND r.enabled
		 WHERE i.status = 'open' AND i.acknowledged_at IS NULL AND i.merged_into IS NULL AND NOT i.flapping
		   AND (i.snoozed_until IS NULL OR i.snoozed_until <= now())
		   AND coalesce(i.reminded_at, i.opened_at) + make_interval(mins => t.reminder_minutes) <= now()
		   AND abs(hashtext(i.tenant_id::text)) % $2 = $1
		 LIMIT 500`, partition, partitions)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (reminder, error) {
		var r reminder
		err := row.Scan(&r.IncidentID, &r.TenantID, &r.RuleID, &r.HostID, &r.Summary, &r.RuleName, &r.Hostname,
			&r.Sev, &r.Detail, &r.OpenedAt, &r.Sent, &r.Timezone)
		return r, err
	})
}

// remind sends one reminder. The count check makes a second evaluator (or a
// retry) a no-op instead of a duplicate.
func (s *store) remind(ctx context.Context, rm reminder, payload []byte) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `
		UPDATE incidents SET reminded_at = now(), reminders_sent = reminders_sent + 1
		 WHERE id = $1 AND tenant_id = $2 AND reminders_sent = $3
		   AND status = 'open' AND acknowledged_at IS NULL`, rm.IncidentID, rm.TenantID, rm.Sent)
	if err != nil || tag.RowsAffected() == 0 {
		return false, err
	}
	chans, onCall, err := s.channels(ctx, tx, rule{ID: rm.RuleID, TenantID: rm.TenantID})
	if err != nil {
		return false, err
	}
	var wanted []channel
	for _, c := range chans {
		if c.wants(rm.Sev) {
			wanted = append(wanted, c)
		}
	}
	held, err := enqueue(ctx, tx, rm.TenantID, wanted, rm.IncidentID, "alert_reminder", rm.Sev, payload, 0)
	if err != nil {
		return false, err
	}
	text := "Reminder sent: nobody has acknowledged it"
	if len(wanted) > 0 {
		text = "Reminded " + describeChannels(wanted)
		if len(onCall) > 0 {
			text += " (on call: " + joinNames(onCall) + ")"
		}
		if held > 0 {
			text += fmt.Sprintf("; %d held for quiet hours", held)
		}
	}
	if err := addEvent(ctx, tx, rm.TenantID, rm.IncidentID, "reminded", text, "alerter"); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func (e *evaluator) remindAll(ctx context.Context, c *cycle, partition, partitions int) {
	due, err := e.store.dueReminders(ctx, partition, partitions)
	if err != nil {
		e.log.Error("loading reminders", "err", err)
		return
	}
	now := time.Now()
	for _, rm := range due {
		if rm.HostID != nil {
			h, err := e.store.host(ctx, rm.TenantID, *rm.HostID)
			if err == nil && inMaintenance(e.maintenanceFor(ctx, c, rm.TenantID), h, now) {
				continue
			}
		}
		payload, err := json.Marshal(e.reminderMessage(rm, now))
		if err != nil {
			continue
		}
		sent, err := e.store.remind(ctx, rm, payload)
		if err != nil {
			e.log.Error("sending a reminder", "incident_id", rm.IncidentID, "err", err)
			continue
		}
		if sent {
			e.log.Info("incident reminder", "incident_id", rm.IncidentID, "n", rm.Sent+1, "tenant_id", rm.TenantID)
		}
	}
}

func (e *evaluator) reminderMessage(rm reminder, now time.Time) message {
	open := now.Sub(rm.OpenedAt).Round(time.Minute)
	text := fmt.Sprintf("STILL OPEN: %s\n\nThis alert has been open for %s and nobody has acknowledged it.\n"+
		"Host: %s\nRule: %s\nOpened: %s\n", rm.Summary, open, rm.Hostname, rm.RuleName, localTime(rm.OpenedAt, rm.Timezone))
	if rm.Detail != nil && *rm.Detail != "" {
		text += "Detail: " + *rm.Detail + "\n"
	}
	text += e.links(rm.IncidentID, true)
	return message{
		Subject: fmt.Sprintf("[Sentinel] STILL OPEN: %s (%s)", rm.Summary, open),
		Text:    text,
		Event: map[string]any{
			"type":        "alert_reminder",
			"summary":     rm.Summary,
			"incident_id": rm.IncidentID,
			"rule_name":   rm.RuleName,
			"hostname":    rm.Hostname,
			"severity":    rm.Sev,
			"detail":      deref(rm.Detail),
			"opened_at":   rm.OpenedAt.UTC().Format(time.RFC3339),
			"at":          now.UTC().Format(time.RFC3339),
			"timezone":    rm.Timezone,
			"open_for":    open.String(),
		},
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
