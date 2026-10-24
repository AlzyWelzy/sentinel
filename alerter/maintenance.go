package main

import (
	"slices"
	"time"
)

// window is a maintenance window: while one covering a host is active, new
// incidents for it aren't opened and nothing is sent about it. A breach that
// outlasts the window fires as soon as the window ends.
type window struct {
	HostID   *string
	Tag      *string
	Schedule string // "once" or "weekly"
	// once
	StartsAt *time.Time
	EndsAt   *time.Time
	// weekly: ISO weekdays (1 = Monday), local start time "HH:MM", length
	Weekdays        []int32
	StartTime       string
	DurationMinutes int
	Timezone        string
}

func (w window) covers(h host) bool {
	switch {
	case w.HostID != nil:
		return *w.HostID == h.ID
	case w.Tag != nil:
		return slices.Contains(h.Tags, *w.Tag)
	}
	return true
}

func (w window) activeAt(now time.Time) bool {
	if w.Schedule == "once" {
		return w.StartsAt != nil && w.EndsAt != nil && !now.Before(*w.StartsAt) && now.Before(*w.EndsAt)
	}
	loc, err := time.LoadLocation(w.Timezone)
	if err != nil {
		loc = time.UTC
	}
	start, err := time.Parse("15:04", w.StartTime)
	if err != nil || w.DurationMinutes <= 0 {
		return false
	}
	length := time.Duration(w.DurationMinutes) * time.Minute
	local := now.In(loc)
	// A window can last up to a week, so one that started on any of the last
	// 7 days (or today) may still be running.
	for back := 0; back <= 7; back++ {
		day := local.AddDate(0, 0, -back)
		if !slices.Contains(w.Weekdays, isoWeekday(day)) {
			continue
		}
		begin := time.Date(day.Year(), day.Month(), day.Day(), start.Hour(), start.Minute(), 0, 0, loc)
		if !now.Before(begin) && now.Before(begin.Add(length)) {
			return true
		}
	}
	return false
}

func isoWeekday(t time.Time) int32 {
	return int32((int(t.Weekday())+6)%7 + 1)
}

func inMaintenance(windows []window, h host, now time.Time) bool {
	for _, w := range windows {
		if w.covers(h) && w.activeAt(now) {
			return true
		}
	}
	return false
}
