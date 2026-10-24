//go:build linux

package collector

import "testing"

func TestUnitName(t *testing.T) {
	cases := map[string]string{"nginx": "nginx.service", "ssh.socket": "ssh.socket", "php8.2-fpm": "php8.2-fpm.service"}
	for in, want := range cases {
		if got := unitName(in); got != want {
			t.Errorf("unitName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseActiveStates(t *testing.T) {
	raw := []byte("ActiveState=active\n\nActiveState=inactive\n\nActiveState=failed\n")
	got := parseActiveStates(raw)
	if len(got) != 3 || got[0] != "active" || got[2] != "failed" {
		t.Errorf("got %v", got)
	}
}
