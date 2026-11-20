package traps

import (
	"strings"
	"testing"
)

func TestCatalogConsistent(t *testing.T) {
	rules := map[string]bool{}
	for _, r := range Rules {
		if rules[r.Key] {
			t.Fatalf("duplicate rule %q", r.Key)
		}
		rules[r.Key] = true
		if !strings.HasPrefix(r.Key, "trap_") || r.Name == "" || r.Help == "" || (r.Severity != "warning" && r.Severity != "critical") {
			t.Errorf("rule %q incomplete", r.Key)
		}
	}
	used := map[string]bool{}
	seen := map[string]bool{}
	for _, tt := range Catalog {
		if seen[tt.OID] {
			t.Errorf("duplicate OID %s", tt.OID)
		}
		seen[tt.OID] = true
		if tt.Rule != "" && !rules[tt.Rule] {
			t.Errorf("%s uses unknown rule %q", tt.Name, tt.Rule)
		}
		if tt.Rule == "" && tt.Action != "" && tt.Action != Event {
			t.Errorf("%s has an action but no rule", tt.Name)
		}
		used[tt.Rule] = true
	}
	for r := range rules {
		if !used[r] {
			t.Errorf("rule %q has no trap", r)
		}
	}
}

func TestClassify(t *testing.T) {
	r := Classify(".1.3.6.1.4.1.12356.101.2.0.302", map[string]string{
		vbVPNPhase1 + ".0": `"to-branch"`, vbVPNRemote: "203.0.113.9", vbSerial: "FG100F", trapCommunity: "secret"})
	if r.Action != Open || r.Rule != "trap_vpn_tunnel_down" || r.Severity != "critical" ||
		r.Labels["tunnel"] != "to-branch" || r.Identity != "tunnel=to-branch remote=203.0.113.9" {
		t.Fatalf("vpn down: %+v", r)
	}
	up := Classify("1.3.6.1.4.1.12356.101.2.0.301", map[string]string{vbVPNPhase1: "to-branch", vbVPNRemote: "203.0.113.9"})
	if up.Action != Clear || up.Identity != r.Identity {
		t.Fatalf("vpn up must clear the same identity: %+v", up)
	}

	bgp := Classify("1.3.6.1.2.1.15.0.2", map[string]string{"1.3.6.1.2.1.15.3.1.14.192.0.2.1": "0x0", "1.3.6.1.2.1.15.3.1.2.192.0.2.1": "2"})
	if bgp.Labels["peer"] != "192.0.2.1" || bgp.Action != Open {
		t.Fatalf("bgp: %+v", bgp)
	}
	ospf := Classify("1.3.6.1.2.1.14.16.2.2", map[string]string{"1.3.6.1.2.1.14.10.1.6.10.0.0.2.0": "8"})
	if ospf.Labels["neighbor"] != "10.0.0.2" || ospf.Labels["state"] != "full" || ospf.Action != Clear {
		t.Fatalf("ospf full: %+v", ospf)
	}
	if Classify("1.3.6.1.2.1.14.16.2.2", map[string]string{"1.3.6.1.2.1.14.10.1.6.10.0.0.2.0": "1"}).Action != Open ||
		Classify("1.3.6.1.2.1.14.16.2.2", map[string]string{"1.3.6.1.2.1.14.10.1.6.10.0.0.2.0": "4"}).Action != Event {
		t.Fatal("ospf transitions")
	}
	if Classify(fgTrap+"1401", map[string]string{"1.3.6.1.4.1.12356.101.5.3.3.1.0": "2"}).Action != Clear ||
		Classify(fgTrap+"1401", map[string]string{"1.3.6.1.4.1.12356.101.5.3.3.1.0": "1"}).Action != Open {
		t.Fatal("pool")
	}
	if Classify(fnTrap+"106", map[string]string{vbGenMsg: "Power supply 2 restored"}).Action != Clear ||
		Classify(fnTrap+"106", map[string]string{vbGenMsg: "Power supply 2 failure"}).Action != Open {
		t.Fatal("power supply")
	}
	unknown := Classify("1.2.3.4", map[string]string{})
	if unknown.Type != nil || unknown.Action != Event {
		t.Fatalf("unknown: %+v", unknown)
	}
	// An event-only trap never carries a rule.
	if e := Classify(fgTrap+"505", nil); e.Action != Event || e.Rule != "" {
		t.Fatalf("event: %+v", e)
	}
}

func TestCommunityNeverKept(t *testing.T) {
	vb := map[string]string{trapCommunity: "secret", "." + trapCommunity: "secret"}
	Classify("1.3.6.1.6.3.1.1.5.1", vb)
	if len(vb) != 0 {
		t.Fatalf("community left in varbinds: %v", vb)
	}
}

func TestAristaMacLearn(t *testing.T) {
	r := Classify("1.3.6.1.4.1.30065.3.2.0.2", map[string]string{"1.3.6.1.2.1.17.7.1.2.2.1.2.1149.2.1.1.72.0.4": "137"})
	if r.Labels["mac"] != "02:01:01:48:00:04" || r.Labels["vlan"] != "1149" || r.Labels["port"] != "137" || r.Identity != "" {
		t.Fatalf("%+v", r)
	}
}

func TestV1FortinetTrap(t *testing.T) {
	up := Lookup(fgTrap + "301")
	if Lookup("1.3.6.1.4.1.12356.101.1.1201.0.301") != up || Lookup(".1.3.6.1.4.1.12356.101.1.1201.0.301") != up {
		t.Fatal("v1 FortiGate trap")
	}
	if Lookup("1.3.6.1.4.1.9.1.1201.0.301") != nil {
		t.Fatal("non-Fortinet enterprise must not match")
	}
	seen := map[string]string{}
	for _, tt := range Catalog {
		for _, p := range []string{fgTrap, fnTrap, fmTrap} {
			if n, ok := strings.CutPrefix(tt.OID, p); ok {
				if prev, dup := seen[n]; dup && prev != p {
					t.Fatalf("trap number %s under both %s and %s", n, prev, p)
				}
				seen[n] = p
			}
		}
	}
}
