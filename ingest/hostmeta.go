package main

import (
	"net"
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
