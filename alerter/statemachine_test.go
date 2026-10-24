package main

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func breach(v float64) observation { return observation{HasData: true, Breached: true, Value: v} }
func healthy() observation         { return observation{HasData: true} }

func TestFiresOnlyAfterDuration(t *testing.T) {
	d := 5 * time.Minute
	s, a := transition(alertState{}, breach(95), d, t0)
	if s.State != statePending || a != actionNone {
		t.Fatalf("first breach: %v %v", s, a)
	}
	s, a = transition(s, breach(95), d, t0.Add(4*time.Minute))
	if s.State != statePending || a != actionNone {
		t.Fatalf("before duration: %v %v", s, a)
	}
	s, a = transition(s, breach(95), d, t0.Add(5*time.Minute))
	if s.State != stateFiring || a != actionOpen {
		t.Fatalf("at duration: %v %v", s, a)
	}
	s, a = transition(s, breach(97), d, t0.Add(6*time.Minute))
	if s.State != stateFiring || a != actionNone {
		t.Fatalf("still firing must not reopen: %v %v", s, a)
	}
	s, a = transition(s, healthy(), d, t0.Add(7*time.Minute))
	if s.State != stateOK || a != actionResolve {
		t.Fatalf("recovery: %v %v", s, a)
	}
}

func TestBlipDoesNotFire(t *testing.T) {
	s, _ := transition(alertState{}, breach(95), time.Minute, t0)
	s, a := transition(s, healthy(), time.Minute, t0.Add(30*time.Second))
	if s.State != stateOK || a != actionNone {
		t.Fatalf("short blip: %v %v", s, a)
	}
}

func TestZeroDurationFiresImmediately(t *testing.T) {
	s, a := transition(alertState{}, breach(1), 0, t0)
	if s.State != stateFiring || a != actionOpen {
		t.Fatalf("%v %v", s, a)
	}
}

func TestNoDataIsNotRecovery(t *testing.T) {
	firing := alertState{State: stateFiring, Since: t0}
	s, a := transition(firing, observation{}, time.Minute, t0.Add(time.Hour))
	if s != firing || a != actionNone {
		t.Fatalf("silence resolved an incident: %v %v", s, a)
	}
}

func TestOperators(t *testing.T) {
	if !breached(">", 91, 90) || breached(">", 90, 90) || !breached("<", 5, 10) || breached("<", 10, 10) {
		t.Fatal("operator semantics wrong")
	}
}

func TestRecentFlipsNeverNil(t *testing.T) {
	now := time.Now()
	if got := recentFlips(nil, now); got == nil || len(got) != 0 {
		t.Fatalf("got %#v", got)
	}
	got := recentFlips([]time.Time{now.Add(-2 * time.Hour), now.Add(-time.Minute)}, now)
	if len(got) != 1 {
		t.Fatalf("got %v", got)
	}
}
