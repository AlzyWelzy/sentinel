package main

import (
	"fmt"
	"testing"
	"time"
)

func fleet(now time.Time, tenants, perTenant int, quiet func(tenant, host int) bool) []seen {
	var out []seen
	for t := range tenants {
		for h := range perTenant {
			at := now.Add(-20 * time.Second)
			if quiet(t, h) {
				at = now.Add(-5 * time.Minute)
			}
			out = append(out, seen{tenant: fmt.Sprint("t", t), at: at})
		}
	}
	return out
}

func TestFleetOutage(t *testing.T) {
	now := time.Now()
	all := func(int, int) bool { return true }
	none := func(int, int) bool { return false }
	cases := []struct {
		name  string
		hosts []seen
		want  bool
	}{
		{"everyone quiet: our outage", fleet(now, 5, 4, all), true},
		{"everyone reporting", fleet(now, 5, 4, none), false},
		// One customer's NAT drops 40 servers; they must still be alerted.
		{"one big organisation quiet", append(fleet(now, 1, 40, all), fleet(now, 3, 1, none)...), false},
		{"one organisation, all quiet: can't tell it from ours", fleet(now, 1, 40, all), false},
		{"too few servers to tell", fleet(now, 3, 1, all), false},
		{"too few organisations to tell", fleet(now, 2, 10, all), false},
		{"half the fleet quiet", fleet(now, 6, 4, func(t, _ int) bool { return t%2 == 0 }), false},
		// Early days: trial servers uninstalled a while ago, then the one
		// real customer goes down. That's their outage, not ours.
		{"abandoned servers don't vote", append(
			oldFleet(now, 4, 3, 20*time.Minute), fleet(now, 1, 3, all)...), false},
	}
	for _, c := range cases {
		if got := fleetOutage(c.hosts, now); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}

// oldFleet: servers that last reported `ago` before now.
func oldFleet(now time.Time, tenants, perTenant int, ago time.Duration) []seen {
	var out []seen
	for t := range tenants {
		for range perTenant {
			out = append(out, seen{tenant: fmt.Sprint("old", t), at: now.Add(-ago)})
		}
	}
	return out
}
