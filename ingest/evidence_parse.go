package main

// Parsing evidence syslog: FortiOS key=value logs (traffic sessions with
// SNAT/DNAT, VPN and authentication events), RFC 5424 and RFC 3164. A line
// that doesn't parse is still stored, whole, with parsed = 0: evidence is
// never thrown away for being in an unexpected format.

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type parsedLog struct {
	Facility, Severity int8
	EventTime          time.Time
	Hostname, Program  string
	Message            string
	Parsed             bool
	KV                 map[string]string // FortiOS fields, when it's one
	IPs                []netip.Addr
}

var (
	priRE    = regexp.MustCompile(`^<(\d{1,3})>`)
	rfc5424  = regexp.MustCompile(`^1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|\[.*?\](?:\[.*?\])*) ?(.*)$`)
	rfc3164  = regexp.MustCompile(`^([A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) (\S+) ([^:\[\s]+)(?:\[\d+\])?: ?(.*)$`)
	ipv4RE   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6RE   = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b|(?i)\b(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{0,4}\b`)
	maxLogIP = 32
)

// parseKV reads FortiOS-style key=value pairs, values optionally quoted.
func parseKV(s string) map[string]string {
	out := map[string]string{}
	i := 0
	for i < len(s) {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		eq := strings.IndexByte(s[i:], '=')
		if eq <= 0 {
			break
		}
		key := s[i : i+eq]
		if strings.ContainsAny(key, " \"") {
			// Not a key: skip to the next space.
			sp := strings.IndexByte(s[i:], ' ')
			if sp < 0 {
				break
			}
			i += sp + 1
			continue
		}
		i += eq + 1
		var val string
		if i < len(s) && s[i] == '"' {
			end := strings.IndexByte(s[i+1:], '"')
			if end < 0 {
				val, i = s[i+1:], len(s)
			} else {
				val, i = s[i+1:i+1+end], i+end+2
			}
		} else {
			end := strings.IndexByte(s[i:], ' ')
			if end < 0 {
				val, i = s[i:], len(s)
			} else {
				val, i = s[i:i+end], i+end
			}
		}
		out[key] = val
	}
	return out
}

func isFortiKV(kv map[string]string) bool {
	return kv["logid"] != "" && (kv["type"] != "" || kv["devname"] != "")
}

func parseLog(line string, received time.Time) parsedLog {
	p := parsedLog{EventTime: received, Facility: -1, Severity: -1}
	rest := line
	if m := priRE.FindStringSubmatch(rest); m != nil {
		if pri, err := strconv.Atoi(m[1]); err == nil && pri <= 191 {
			p.Facility, p.Severity = int8(pri/8), int8(pri%8)
		}
		rest = rest[len(m[0]):]
	}
	if m := rfc5424.FindStringSubmatch(rest); m != nil {
		if t, err := time.Parse(time.RFC3339Nano, m[1]); err == nil {
			p.EventTime = t.UTC()
		}
		p.Hostname, p.Program, p.Message, p.Parsed = nilDash(m[2]), nilDash(m[3]), m[7], true
	} else if m := rfc3164.FindStringSubmatch(rest); m != nil {
		if t, err := time.Parse("Jan _2 15:04:05", m[1]); err == nil {
			// No year or zone in RFC 3164: the receive year, read as UTC.
			t = time.Date(received.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
			if t.After(received.Add(24 * time.Hour)) {
				t = t.AddDate(-1, 0, 0)
			}
			p.EventTime = t
		}
		p.Hostname, p.Program, p.Message, p.Parsed = m[2], m[3], m[4], true
	} else {
		p.Message = strings.TrimSpace(rest)
	}
	kv := parseKV(p.Message)
	if !isFortiKV(kv) {
		kv = parseKV(strings.TrimSpace(rest))
	}
	if isFortiKV(kv) {
		p.KV, p.Parsed = kv, true
		p.Hostname = orDefaultStr(kv["devname"], p.Hostname)
		p.Program = "fortios"
		if t := fortiTime(kv); !t.IsZero() {
			p.EventTime = t
		}
	}
	p.IPs = extractIPs(line)
	return p
}

func nilDash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func orDefaultStr(v, d string) string {
	if v != "" {
		return v
	}
	return d
}

// fortiTime prefers eventtime (ns/us/ms/s since epoch, by size), then
// date + time + tz.
func fortiTime(kv map[string]string) time.Time {
	if v, err := strconv.ParseInt(kv["eventtime"], 10, 64); err == nil && v > 0 {
		switch {
		case v > 1e17:
			return time.Unix(0, v).UTC()
		case v > 1e14:
			return time.UnixMicro(v).UTC()
		case v > 1e11:
			return time.UnixMilli(v).UTC()
		default:
			return time.Unix(v, 0).UTC()
		}
	}
	if kv["date"] != "" && kv["time"] != "" {
		layout, val := "2006-01-02 15:04:05", kv["date"]+" "+kv["time"]
		if tz := kv["tz"]; tz != "" {
			if t, err := time.Parse(layout+" -0700", val+" "+strings.Trim(tz, `"`)); err == nil {
				return t.UTC()
			}
		}
		if t, err := time.Parse(layout, val); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func extractIPs(s string) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, re := range []*regexp.Regexp{ipv4RE, ipv6RE} {
		for _, m := range re.FindAllString(s, -1) {
			a, err := netip.ParseAddr(m)
			if err != nil || seen[a] || a.IsUnspecified() {
				continue
			}
			seen[a] = true
			out = append(out, a)
			if len(out) >= maxLogIP {
				return out
			}
		}
	}
	return out
}

// addr parses an IP field, '::' when absent (ClickHouse IPv6 has no null).
func addr(s string) netip.Addr {
	if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
		return a
	}
	return netip.IPv6Unspecified()
}

func u64(s string) uint64 {
	v, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	return v
}

// ip6 is the IPv6 form ClickHouse stores (IPv4 as ::ffff:a.b.c.d).
func ip6(a netip.Addr) string {
	if !a.IsValid() {
		return "::"
	}
	if a.Is4() {
		return netip.AddrFrom16(a.As16()).String()
	}
	return a.String()
}

// identityEvent reports whether a FortiOS event ties an IP to a user (VPN
// tunnel up, firewall authentication), and which IP.
func identityEvent(kv map[string]string) (ip, user, action string, ok bool) {
	user = kv["user"]
	if user == "" || user == "N/A" {
		return "", "", "", false
	}
	switch kv["subtype"] {
	case "vpn":
		ip = orDefaultStr(kv["tunnelip"], kv["assignip"])
		if ip == "" || ip == "N/A" || ip == "(null)" {
			ip = kv["remip"]
		}
	case "user", "system":
		ip = orDefaultStr(kv["srcip"], kv["remip"])
	default:
		return "", "", "", false
	}
	if !addr(ip).IsValid() || addr(ip).IsUnspecified() {
		return "", "", "", false
	}
	return ip, user, orDefaultStr(kv["action"], kv["status"]), true
}
