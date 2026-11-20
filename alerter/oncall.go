package main

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// On-call and quiet hours, decided the same way as api/app/services/oncall.py.

type responder struct {
	Name       string   `json:"name"`
	ChannelIDs []string `json:"channel_ids"`
}

type schedule struct {
	ID         string
	StartAt    time.Time
	ShiftHours int
	Location   *time.Location // the schedule's time zone; nil means UTC
	Responders []responder
	Overrides  []override // newest first
}

type override struct {
	StartsAt, EndsAt time.Time
	Responder        responder
}

// onCall is who is on call at t: the newest override covering t, else whose
// turn it is in the rotation.
func (s schedule) onCall(t time.Time) (responder, bool) {
	for _, o := range s.Overrides {
		if !t.Before(o.StartsAt) && t.Before(o.EndsAt) {
			return o.Responder, true
		}
	}
	if len(s.Responders) == 0 || s.ShiftHours <= 0 {
		return responder{}, false
	}
	if t.Before(s.StartAt) {
		return s.Responders[0], true
	}
	k := int(t.Sub(s.StartAt) / (time.Duration(s.ShiftHours) * time.Hour))
	// A daylight-saving change moves whole-day boundaries by up to an hour.
	for !s.boundary(k + 1).After(t) {
		k++
	}
	for k > 0 && s.boundary(k).After(t) {
		k--
	}
	return s.Responders[k%len(s.Responders)], true
}

// boundary is when shift k begins. Shifts of whole days keep their local
// start time across daylight-saving changes (a 09:00 handoff stays at
// 09:00); other lengths are exact hours.
func (s schedule) boundary(k int) time.Time {
	if s.ShiftHours%24 == 0 {
		loc := s.Location
		if loc == nil {
			loc = time.UTC
		}
		return s.StartAt.In(loc).AddDate(0, 0, k*s.ShiftHours/24)
	}
	return s.StartAt.Add(time.Duration(k*s.ShiftHours) * time.Hour)
}

// loadSchedules reads a tenant's schedules (and live overrides) by id.
func loadSchedules(ctx context.Context, tx pgx.Tx, tenantID string, ids []string) ([]schedule, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT id, start_at, shift_hours, responders, timezone FROM oncall_schedules
		 WHERE tenant_id = $1 AND id = ANY ($2::uuid[])`, tenantID, ids)
	if err != nil {
		return nil, err
	}
	byID := map[string]*schedule{}
	var order []string
	for rows.Next() {
		var s schedule
		var raw []byte
		var tz string
		if err := rows.Scan(&s.ID, &s.StartAt, &s.ShiftHours, &raw, &tz); err != nil {
			rows.Close()
			return nil, err
		}
		if loc, err := time.LoadLocation(tz); err == nil {
			s.Location = loc
		}
		_ = json.Unmarshal(raw, &s.Responders)
		byID[s.ID] = &s
		order = append(order, s.ID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = tx.Query(ctx, `
		SELECT schedule_id, starts_at, ends_at, responder FROM oncall_overrides
		 WHERE tenant_id = $1 AND schedule_id = ANY ($2::uuid[]) AND ends_at > now()
		 ORDER BY created_at DESC`, tenantID, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sid string
		var o override
		var raw []byte
		if err := rows.Scan(&sid, &o.StartsAt, &o.EndsAt, &raw); err != nil {
			rows.Close()
			return nil, err
		}
		_ = json.Unmarshal(raw, &o.Responder)
		if s := byID[sid]; s != nil {
			s.Overrides = append(s.Overrides, o)
		}
	}
	rows.Close()
	out := make([]schedule, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out, rows.Err()
}

// onCallChannels: the verified contacts of whoever is on call now in these
// schedules, and who that is (for the incident timeline).
func onCallChannels(ctx context.Context, tx pgx.Tx, tenantID string, scheduleIDs []string, now time.Time) ([]channel, []string, error) {
	schedules, err := loadSchedules(ctx, tx, tenantID, scheduleIDs)
	if err != nil || len(schedules) == 0 {
		return nil, nil, err
	}
	var ids, who []string
	for _, s := range schedules {
		if r, ok := s.onCall(now); ok {
			ids = append(ids, r.ChannelIDs...)
			who = append(who, r.Name)
		}
	}
	if len(ids) == 0 {
		return nil, who, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT id, type, target, config, min_severity, quiet_hours, only_tag FROM notification_channels
		 WHERE tenant_id = $1 AND id = ANY ($2::uuid[]) AND verified_at IS NOT NULL`, tenantID, ids)
	if err != nil {
		return nil, nil, err
	}
	chans, err := pgx.CollectRows(rows, scanChannel)
	return chans, who, err
}

// mergeChannels keeps each contact once, in order.
func mergeChannels(lists ...[]channel) []channel {
	seen := map[string]bool{}
	var out []channel
	for _, l := range lists {
		for _, c := range l {
			if !seen[c.ID] {
				seen[c.ID] = true
				out = append(out, c)
			}
		}
	}
	return out
}

type quietHours struct {
	Start                 string `json:"start"`
	End                   string `json:"end"`
	Timezone              string `json:"timezone"`
	CriticalBreaksThrough *bool  `json:"critical_breaks_through"`
}

func hhmm(s string) (int, bool) {
	h, m, ok := strings.Cut(s, ":")
	if !ok {
		return 0, false
	}
	hi, err1 := strconv.Atoi(h)
	mi, err2 := strconv.Atoi(m)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return hi*60 + mi, true
}

// quietUntil is when a held message may go out, or the zero time to send now.
func (q *quietHours) quietUntil(severity string, now time.Time) time.Time {
	if q == nil {
		return time.Time{}
	}
	breaks := q.CriticalBreaksThrough == nil || *q.CriticalBreaksThrough
	if severity == "critical" && breaks {
		return time.Time{}
	}
	start, ok1 := hhmm(q.Start)
	end, ok2 := hhmm(q.End)
	if !ok1 || !ok2 || start == end {
		return time.Time{}
	}
	loc, err := time.LoadLocation(q.Timezone)
	if err != nil || q.Timezone == "" {
		loc = time.UTC
	}
	local := now.In(loc)
	cur := local.Hour()*60 + local.Minute()
	overnight := start > end
	inside := (overnight && (cur >= start || cur < end)) || (!overnight && cur >= start && cur < end)
	if !inside {
		return time.Time{}
	}
	day := local
	if overnight && cur >= start {
		day = day.AddDate(0, 0, 1)
	}
	return time.Date(day.Year(), day.Month(), day.Day(), end/60, end%60, 0, 0, loc).UTC()
}

// sortByName keeps who-is-on-call text stable in timelines.
func joinNames(names []string) string {
	sort.Strings(names)
	return strings.Join(names, ", ")
}
