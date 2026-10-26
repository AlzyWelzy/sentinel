package main

import (
	"testing"
	"time"
)

// Same cases as api/tests/test_oncall.py.
func TestOnCallRotation(t *testing.T) {
	start := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	s := schedule{StartAt: start, ShiftHours: 24, Responders: []responder{{Name: "Asha"}, {Name: "Ravi"}, {Name: "Meera"}}}
	cases := map[time.Duration]string{-time.Hour: "Asha", 0: "Asha", 23 * time.Hour: "Asha", 24 * time.Hour: "Ravi", 72 * time.Hour: "Asha", 50 * time.Hour: "Meera"}
	for offset, want := range cases {
		if got, _ := s.onCall(start.Add(offset)); got.Name != want {
			t.Fatalf("at +%s: %s, want %s", offset, got.Name, want)
		}
	}
	s.Overrides = []override{
		{StartsAt: start.Add(25 * time.Hour), EndsAt: start.Add(30 * time.Hour), Responder: responder{Name: "Cover (newest)"}},
		{StartsAt: start.Add(24 * time.Hour), EndsAt: start.Add(48 * time.Hour), Responder: responder{Name: "Cover"}},
	}
	if got, _ := s.onCall(start.Add(26 * time.Hour)); got.Name != "Cover (newest)" {
		t.Fatalf("the newest covering override wins: %s", got.Name)
	}
	if got, _ := s.onCall(start.Add(31 * time.Hour)); got.Name != "Cover" {
		t.Fatalf("override: %s", got.Name)
	}
	if _, ok := (schedule{ShiftHours: 24}).onCall(start); ok {
		t.Fatal("nobody on call without responders")
	}
}

func TestQuietUntil(t *testing.T) {
	no := false
	q := &quietHours{Start: "22:00", End: "07:00", Timezone: "Asia/Kolkata"}
	ist := time.FixedZone("IST", 5*3600+1800)
	late := time.Date(2026, 10, 26, 23, 30, 0, 0, ist)
	want := time.Date(2026, 10, 27, 7, 0, 0, 0, ist).UTC()
	if got := q.quietUntil("warning", late); !got.Equal(want) {
		t.Fatalf("23:30 holds until 07:00 next day: %s", got)
	}
	early := time.Date(2026, 10, 27, 6, 0, 0, 0, ist)
	if got := q.quietUntil("warning", early); !got.Equal(want) {
		t.Fatalf("06:00 holds until 07:00 the same day: %s", got)
	}
	if got := q.quietUntil("warning", time.Date(2026, 10, 27, 12, 0, 0, 0, ist)); !got.IsZero() {
		t.Fatal("midday isn't quiet")
	}
	if got := q.quietUntil("critical", late); !got.IsZero() {
		t.Fatal("critical breaks through by default")
	}
	q.CriticalBreaksThrough = &no
	if got := q.quietUntil("critical", late); got.IsZero() {
		t.Fatal("unless the contact says otherwise")
	}
	var none *quietHours
	if !none.quietUntil("info", late).IsZero() {
		t.Fatal("no quiet hours: send now")
	}
}
