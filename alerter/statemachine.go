package main

import "time"

// Alert states for one (rule, host) pair:
//
//	ok ──breach──▶ pending ──breach for ≥ duration──▶ firing
//	 ▲               │                                  │
//	 └──recovers─────┘◀──────────── recovers ───────────┘ (incident resolved)
//
// "No data" changes nothing: a host that stops reporting must not look like
// it recovered. The host_down rule is what catches silence.

const (
	stateOK      = "ok"
	statePending = "pending"
	stateFiring  = "firing"
)

type action int

const (
	actionNone action = iota
	actionOpen
	actionResolve
)

type alertState struct {
	State string
	Since time.Time
}

type observation struct {
	HasData  bool
	Breached bool
	Value    float64
	Total    float64 // probe checks: how many locations reported
	Detail   string  // check rules: the latest result text
}

func transition(cur alertState, obs observation, duration time.Duration, now time.Time) (alertState, action) {
	if cur.State == "" {
		cur = alertState{State: stateOK, Since: now}
	}
	if !obs.HasData {
		return cur, actionNone
	}
	switch {
	case obs.Breached && cur.State == stateOK:
		if duration <= 0 {
			return alertState{State: stateFiring, Since: now}, actionOpen
		}
		return alertState{State: statePending, Since: now}, actionNone
	case obs.Breached && cur.State == statePending:
		if now.Sub(cur.Since) >= duration {
			return alertState{State: stateFiring, Since: now}, actionOpen
		}
		return cur, actionNone
	case !obs.Breached && cur.State == statePending:
		return alertState{State: stateOK, Since: now}, actionNone
	case !obs.Breached && cur.State == stateFiring:
		return alertState{State: stateOK, Since: now}, actionResolve
	}
	return cur, actionNone
}

func breached(operator string, value, threshold float64) bool {
	if operator == "<" {
		return value < threshold
	}
	return value > threshold
}
