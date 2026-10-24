package main

import (
	"testing"
	"time"
)

func ptr[T any](v T) *T { return &v }

func TestOnceWindow(t *testing.T) {
	start := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	w := window{Schedule: "once", StartsAt: ptr(start), EndsAt: ptr(start.Add(time.Hour))}
	if !w.activeAt(start) || !w.activeAt(start.Add(59*time.Minute)) {
		t.Error("should be active inside [start, end)")
	}
	if w.activeAt(start.Add(-time.Second)) || w.activeAt(start.Add(time.Hour)) {
		t.Error("should be inactive outside")
	}
}

func TestWeeklyWindowAcrossMidnightInTimezone(t *testing.T) {
	// Saturdays 23:00 IST for 2 hours, i.e. until Sunday 01:00 IST.
	w := window{Schedule: "weekly", Weekdays: []int32{6}, StartTime: "23:00", DurationMinutes: 120, Timezone: "Asia/Kolkata"}
	ist, _ := time.LoadLocation("Asia/Kolkata")
	sat := time.Date(2026, 10, 24, 23, 30, 0, 0, ist) // a Saturday
	if !w.activeAt(sat) {
		t.Error("Saturday 23:30 IST should be inside")
	}
	if !w.activeAt(sat.Add(time.Hour)) {
		t.Error("Sunday 00:30 IST should still be inside (started Saturday)")
	}
	if w.activeAt(sat.Add(2 * time.Hour)) {
		t.Error("Sunday 01:30 IST should be outside")
	}
	if w.activeAt(sat.Add(-24 * time.Hour)) {
		t.Error("Friday should be outside")
	}
}

func TestWindowScope(t *testing.T) {
	h := host{ID: "h1", Tags: []string{"web"}}
	if !(window{}).covers(h) {
		t.Error("an unscoped window covers every host")
	}
	if !(window{Tag: ptr("web")}).covers(h) || (window{Tag: ptr("db")}).covers(h) {
		t.Error("tag scope")
	}
	if (window{HostID: ptr("h2")}).covers(h) {
		t.Error("host scope")
	}
}

func TestLegacyTimezoneNames(t *testing.T) {
	// Browsers still report the old names; they must not fall back to UTC.
	w := window{Schedule: "weekly", Weekdays: []int32{6}, StartTime: "23:00", DurationMinutes: 60, Timezone: "Asia/Calcutta"}
	ist, _ := time.LoadLocation("Asia/Kolkata")
	if !w.activeAt(time.Date(2026, 10, 24, 23, 30, 0, 0, ist)) {
		t.Error("Asia/Calcutta must mean IST")
	}
}
