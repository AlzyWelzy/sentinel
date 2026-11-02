package main

import (
	"strings"
	"testing"
)

func hostDownItem(id, ch, chType, kind, host string) outboxItem {
	return outboxItem{ID: id, Kind: kind, Channel: channel{ID: ch, Type: chType},
		Payload: message{Subject: host, Event: map[string]any{"kind": "host_down", "type": kind, "hostname": host, "summary": host}}}
}

func TestGroupHostDownMergesPerContact(t *testing.T) {
	items := []outboxItem{
		hostDownItem("1", "a", "email", "alert_firing", "web2"),
		hostDownItem("2", "a", "email", "alert_firing", "web1"),
		hostDownItem("3", "b", "email", "alert_firing", "web1"),
		hostDownItem("4", "a", "webhook", "alert_firing", "web3"),
		hostDownItem("5", "a", "email", "alert_resolved", "web9"),
		{ID: "6", Kind: "alert_firing", Channel: channel{ID: "a", Type: "email"}, Payload: message{Event: map[string]any{"kind": "metric"}}},
	}
	out := groupHostDown(items)
	if len(out) != 5 {
		t.Fatalf("got %d sends", len(out))
	}
	g := out[0]
	if strings.Join(g.ids, ",") != "1,2" {
		t.Fatalf("ids %v", g.ids)
	}
	if g.item.Payload.Subject != "[Pulsegrid] FIRING: 2 servers are not reporting" {
		t.Fatalf("subject %q", g.item.Payload.Subject)
	}
	if g.item.Payload.Event["hostname"] != "web1, web2" || !strings.Contains(g.item.Payload.Text, "- web1\n- web2") {
		t.Fatalf("hosts %v / %q", g.item.Payload.Event["hostname"], g.item.Payload.Text)
	}
	if renderHTML(g.item.Payload) == "" {
		t.Fatal("merged email has no HTML part")
	}
}

func TestGroupHostDownLeavesRetriesAlone(t *testing.T) {
	a := hostDownItem("1", "a", "email", "alert_firing", "web1")
	b := hostDownItem("2", "a", "email", "alert_firing", "web2")
	b.Attempts = 1
	if out := groupHostDown([]outboxItem{a, b}); len(out) != 2 {
		t.Fatalf("got %d sends", len(out))
	}
}
