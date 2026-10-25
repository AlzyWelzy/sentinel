package main

import (
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// Limits on what an agent can store about its host. The agent is on a
// customer's machine, so everything it sends is cleaned up first.
const (
	maxTags        = 20
	maxIPAddresses = 16
	maxHostnameLen = 253
)

// tagRe matches api/app/routes/v1.py TAG_RE: lowercase, starts with a letter
// or digit.
var tagRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,39}$`)

// normalizeTags lowercases and trims tags, drops invalid ones and duplicates,
// and sorts them. It never returns nil (the column is NOT NULL).
func normalizeTags(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if tagRe.MatchString(t) && !seen[t] && len(out) < maxTags {
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// cleanIPs keeps valid addresses in canonical form. It never returns nil, so
// an agent reporting none clears the column rather than leaving it stale.
func cleanIPs(in []string) []string {
	out := []string{}
	for _, s := range in {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil && len(out) < maxIPAddresses {
			out = append(out, ip.String())
		}
	}
	return out
}

func cleanHostname(h string) string {
	h = strings.TrimSpace(h)
	if len(h) > maxHostnameLen || strings.ContainsAny(h, "\x00\r\n") {
		return ""
	}
	return h
}

// publicClientIP is the public address the agent connects from, or "" when
// there isn't one (a private network, or a test). Forwarding headers count
// only when the request came through a proxy on a private address; the
// X-Forwarded-For chain is read from the right, skipping our own private
// hops, so a client can't claim an address by prepending one.
func publicClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil {
		return ""
	}
	if !peer.IsPrivate() && !peer.IsLoopback() {
		return publicOrEmpty(peer)
	}
	var hops []string
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		hops = strings.Split(xff, ",")
	}
	for i := len(hops) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(hops[i]))
		if ip == nil {
			return ""
		}
		if ip.IsPrivate() || ip.IsLoopback() {
			continue
		}
		return publicOrEmpty(ip)
	}
	if ip := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); ip != nil {
		return publicOrEmpty(ip)
	}
	return ""
}

func publicOrEmpty(ip net.IP) string {
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || cgnat.Contains(ip) {
		return ""
	}
	return ip.String()
}

// 100.64.0.0/10: carrier-grade NAT, shared by many customers.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}
