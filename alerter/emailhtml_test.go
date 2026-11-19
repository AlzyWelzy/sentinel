package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// roundTrip is what the outbox does to an event: JSON in, JSON out.
func roundTrip(t *testing.T, m message) message {
	t.Helper()
	b, err := json.Marshal(m.Event)
	if err != nil {
		t.Fatal(err)
	}
	m.Event = nil
	if err := json.Unmarshal(b, &m.Event); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestAlertEmailShowsTheOrganisationsTime(t *testing.T) {
	m := roundTrip(t, message{Text: "Acknowledge (stops escalation): https://x/ack\n", Event: map[string]any{
		"type": "alert", "severity": "critical", "summary": "Disk above 90% on <b>web</b>",
		"condition": "Disk is 95%", "hostname": "<script>alert(1)</script>", "rule_name": "Disk",
		"at": "2026-11-19T13:00:00Z", "timezone": "Asia/Kolkata", "url": "https://x/incidents/1",
	}})
	h := renderHTML(m)
	if !strings.Contains(h, "Thu 19 Nov 2026, 6:30 PM IST") {
		t.Fatal("time not in the organisation's zone")
	}
	if strings.Contains(h, "<script>alert(1)") || strings.Contains(h, "<b>web</b>") {
		t.Fatal("hostname or summary not escaped")
	}
	if !strings.Contains(h, `href="https://x/ack"`) || strings.Contains(h, "console") {
		t.Fatal("acknowledge link missing, or the old console wording is back")
	}
}

func TestEscalationEmailKeepsItsStepThroughTheOutbox(t *testing.T) {
	e := &evaluator{}
	opened := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	m := roundTrip(t, e.escalationMessage(escalation{
		IncidentID: "i", Summary: "Server not reporting", Hostname: "db-1", RuleName: "Down",
		OpenedAt: opened, Level: 1, Steps: 3, Timezone: "America/New_York",
	}, opened.Add(65*time.Minute)))
	h := renderHTML(m)
	for _, want := range []string{"Escalated · step 2", "Unacknowledged for", "1h 5m", "Thu 19 Nov 2026, 5:00 AM EST"} {
		if !strings.Contains(h, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestResolvedEmailHasNoAcknowledge(t *testing.T) {
	h := renderHTML(message{Text: "Acknowledge (stops escalation): https://x/ack\n", Event: map[string]any{
		"type": "alert_resolved", "summary": "Disk fine", "at": "2026-11-19T13:00:00Z", "timezone": "Nope/Unknown",
	}})
	if strings.Contains(h, "https://x/ack") || !strings.Contains(h, "Cleared") || !strings.Contains(h, "1:00 PM UTC") {
		t.Fatal("resolved email wrong")
	}
}

func TestLocalTimeNamesOffsetOnlyZones(t *testing.T) {
	got := localTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), "Asia/Dubai")
	if !strings.HasSuffix(got, "+04 (Asia/Dubai)") {
		t.Fatal(got)
	}
}
