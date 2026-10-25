package main

import (
	"net/http/httptest"
	"testing"
)

func TestPublicClientIP(t *testing.T) {
	cases := []struct {
		name, remote, xff, real, want string
	}{
		{"direct public", "203.0.113.7:5000", "", "", "203.0.113.7"},
		{"direct ignores headers", "203.0.113.7:5000", "198.51.100.1", "", "203.0.113.7"},
		{"via proxy", "10.0.3.5:4000", "203.0.113.7", "", "203.0.113.7"},
		{"spoofed prefix ignored", "10.0.3.5:4000", "198.51.100.1, 203.0.113.7, 10.0.0.2", "", "203.0.113.7"},
		{"real ip fallback", "10.0.3.5:4000", "", "203.0.113.7", "203.0.113.7"},
		{"private only", "10.0.3.5:4000", "172.16.1.2", "", ""},
		{"cgnat", "100.70.1.1:4000", "", "", ""},
		{"garbage", "10.0.3.5:4000", "not-an-ip", "", ""},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/v1/metrics", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if c.real != "" {
			r.Header.Set("X-Real-IP", c.real)
		}
		if got := publicClientIP(r); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
