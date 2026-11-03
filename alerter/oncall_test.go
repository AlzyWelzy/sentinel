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

// A daily 09:00 London handoff stays at 09:00 local when the clocks change
// (25 Oct 2026 back, 29 Mar 2027 forward); a 12-hour rotation stays exact.
func TestOnCallDailyHandoffKeepsLocalTime(t *testing.T) {
	london, _ := time.LoadLocation("Europe/London")
	s := schedule{
		StartAt: time.Date(2026, 10, 20, 9, 0, 0, 0, london), ShiftHours: 24, Location: london,
		Responders: []responder{{Name: "a"}, {Name: "b"}},
	}
	for _, d := range []int{26, 27, 28} { // after the change: 09:00 GMT, not 08:00 or 10:00
		before := time.Date(2026, 10, d, 8, 59, 0, 0, london)
		after := time.Date(2026, 10, d, 9, 1, 0, 0, london)
		rb, _ := s.onCall(before)
		ra, _ := s.onCall(after)
		if rb.Name == ra.Name {
			t.Errorf("no handoff at 09:00 on %d Oct: %s both sides", d, ra.Name)
		}
	}
	spring := schedule{
		StartAt: time.Date(2027, 3, 26, 9, 0, 0, 0, london), ShiftHours: 24, Location: london,
		Responders: []responder{{Name: "a"}, {Name: "b"}},
	}
	rb, _ := spring.onCall(time.Date(2027, 3, 30, 8, 59, 0, 0, london))
	ra, _ := spring.onCall(time.Date(2027, 3, 30, 9, 1, 0, 0, london))
	if rb.Name == ra.Name {
		t.Error("no handoff at 09:00 after the spring change")
	}
	half := schedule{StartAt: time.Date(2026, 10, 24, 9, 0, 0, 0, london), ShiftHours: 12, Location: london,
		Responders: []responder{{Name: "a"}, {Name: "b"}}}
	r, _ := half.onCall(time.Date(2026, 10, 24, 9, 0, 0, 0, london).Add(36*time.Hour + time.Minute))
	if r.Name != "b" {
		t.Errorf("12-hour rotation: %s after three shifts", r.Name)
	}
}
