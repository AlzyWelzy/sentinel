package snmp

import "testing"

func TestDialPrefersIPv4ForNames(t *testing.T) {
	c, err := Dial("localhost:1161", Credential{Version: "2c", Community: "x"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.g.Target != "127.0.0.1" {
		t.Fatalf("localhost dialled as %s, want 127.0.0.1", c.g.Target)
	}
	if _, err := Dial("no-such-host.invalid", Credential{Version: "2c"}, Options{}); err == nil {
		t.Fatal("unresolvable name accepted")
	}
}
