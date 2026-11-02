package main

import (
	"strings"
	"testing"
)

func TestNormalizeTags(t *testing.T) {
	got := normalizeTags([]string{" Web ", "web", "prod", "-bad", "has space", "", strings.Repeat("x", 41)})
	if strings.Join(got, ",") != "prod,web" {
		t.Errorf("got %v", got)
	}
	if normalizeTags(nil) == nil {
		t.Error("must be an empty slice, not nil (the column is NOT NULL)")
	}
}

func TestCleanIPs(t *testing.T) {
	got := cleanIPs([]string{"103.129.97.14", "not-an-ip", "2001:DB8::5"})
	if strings.Join(got, ",") != "103.129.97.14,2001:db8::5" {
		t.Errorf("got %v", got)
	}
}

func TestCleanHostname(t *testing.T) {
	if cleanHostname("web-1\n") != "web-1" || cleanHostname("a\x00b") != "" {
		t.Error("hostname not cleaned")
	}
}

func TestCleanField(t *testing.T) {
	cases := map[string]string{
		"linux\r\nBcc: x": "linuxBcc: x",
		"  ubuntu\x00 ":   "ubuntu",
		"\xff\xfeok":      "ok",
	}
	for in, want := range cases {
		if got := cleanField(in, 100); got != want {
			t.Errorf("cleanField(%q) = %q, want %q", in, got, want)
		}
	}
	if got := cleanField("ééééé", 5); got != "éé" {
		t.Errorf("cut mid-character: %q", got)
	}
}
