package main

import "testing"

func TestRangeAddrs(t *testing.T) {
	cases := map[string][2]string{ // first, last
		"10.0.0.0/30":    {"10.0.0.1", "10.0.0.2"},
		"10.0.0.7/29":    {"10.0.0.1", "10.0.0.6"}, // host bits ignored
		"10.0.0.4/31":    {"10.0.0.4", "10.0.0.5"},
		"192.168.1.9/32": {"192.168.1.9", "192.168.1.9"},
	}
	for cidr, want := range cases {
		got, err := rangeAddrs(cidr)
		if err != nil || got[0].String() != want[0] || got[len(got)-1].String() != want[1] {
			t.Errorf("%s: %v %v", cidr, got, err)
		}
	}
	big, _ := rangeAddrs("10.0.0.0/16")
	if len(big) != discoveryMax {
		t.Fatalf("a /16 must be capped at %d, got %d", discoveryMax, len(big))
	}
	if _, err := rangeAddrs("not a range"); err == nil {
		t.Fatal("garbage accepted")
	}
}
