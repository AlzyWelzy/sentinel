package checks

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

const (
	diagnoseTimeout = 20 * time.Second
	// While a check keeps failing, diagnose again at most this often.
	rediagnoseAfter = 10 * time.Minute
	maxAddresses    = 4
	maxHops         = 20
)

// target splits a check's target into the host to resolve and the port to
// connect to. ok is false for checks that aren't about a network endpoint.
func target(c proto.Check) (host, port string, ok bool) {
	switch c.Type {
	case "tcp":
		h, p, err := net.SplitHostPort(c.Target)
		return h, p, err == nil
	case "ping":
		return c.Target, "443", c.Target != ""
	case "tls":
		h, p, err := net.SplitHostPort(c.Target)
		if err != nil {
			return c.Target, "443", c.Target != ""
		}
		return h, p, true
	case "dns":
		return c.Target, "", c.Target != ""
	case "http":
		u, err := url.Parse(c.Target)
		if err != nil || u.Hostname() == "" {
			return "", "", false
		}
		p := u.Port()
		if p == "" {
			p = map[string]string{"https": "443"}[u.Scheme]
			if p == "" {
				p = "80"
			}
		}
		return u.Hostname(), p, true
	}
	return "", "", false
}

// diagnose looks into a failed network check. publicOnly (probes) skips
// private addresses, as the check itself does.
func diagnose(ctx context.Context, c proto.Check, publicOnly bool) *proto.Diagnosis {
	host, port, ok := target(c)
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, diagnoseTimeout)
	defer cancel()
	d := &proto.Diagnosis{}

	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else {
		start := time.Now()
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		step := &proto.DNSStep{Host: host, ElapsedMs: ms(time.Since(start))}
		if err != nil {
			step.Error = cleanErr(err)
		}
		for _, ip := range ips {
			step.Addresses = append(step.Addresses, ip.Unmap().String())
			addrs = append(addrs, ip.Unmap())
		}
		d.DNS = step
	}
	if publicOnly {
		var public []netip.Addr
		for _, a := range addrs {
			if publicAddress(a) {
				public = append(public, a)
			}
		}
		addrs = public
	}
	if len(addrs) > maxAddresses {
		addrs = addrs[:maxAddresses]
	}

	if port != "" {
		for _, a := range addrs {
			addr := net.JoinHostPort(a.String(), port)
			start := time.Now()
			conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
			step := proto.ConnectStep{Address: addr, ElapsedMs: ms(time.Since(start))}
			if err != nil {
				step.Error = cleanErr(err)
			} else {
				step.OK = true
				conn.Close()
			}
			d.Connect = append(d.Connect, step)
		}
	}

	// Trace the path to the first address that refused or timed out (or the
	// first address, for a DNS-level failure that still resolved).
	var traceTo netip.Addr
	for i, step := range d.Connect {
		if !step.OK {
			traceTo = addrs[i]
			break
		}
	}
	if !traceTo.IsValid() && len(d.Connect) == 0 && len(addrs) > 0 {
		traceTo = addrs[0]
	}
	if traceTo.IsValid() {
		d.Path, d.PathNote = tracePath(ctx, traceTo, maxHops)
	}
	d.Summary = summarize(d)
	return d
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// summarize says in one line where it breaks.
func summarize(d *proto.Diagnosis) string {
	var parts []string
	if d.DNS != nil {
		switch {
		case d.DNS.Error != "":
			parts = append(parts, fmt.Sprintf("DNS failed for %s: %s", d.DNS.Host, d.DNS.Error))
		case len(d.DNS.Addresses) == 0:
			parts = append(parts, fmt.Sprintf("DNS returned no address for %s", d.DNS.Host))
		default:
			parts = append(parts, fmt.Sprintf("DNS ok (%s, %.0f ms)", strings.Join(d.DNS.Addresses, ", "), d.DNS.ElapsedMs))
		}
	}
	ok, bad := 0, []string{}
	for _, c := range d.Connect {
		if c.OK {
			ok++
		} else {
			bad = append(bad, c.Address+" "+c.Error)
		}
	}
	if len(d.Connect) > 0 {
		if len(bad) == 0 {
			parts = append(parts, fmt.Sprintf("TCP connects to all %d address(es)", ok))
		} else {
			parts = append(parts, "TCP to "+strings.Join(bad, "; "))
		}
	}
	if len(d.Path) > 0 {
		last := d.Path[len(d.Path)-1]
		lastSeen := ""
		for i := len(d.Path) - 1; i >= 0; i-- {
			if d.Path[i].Address != "" {
				lastSeen = d.Path[i].Address
				break
			}
		}
		switch {
		case last.Reached:
			parts = append(parts, fmt.Sprintf("path reaches the server in %d hops", last.TTL))
		case lastSeen != "":
			parts = append(parts, fmt.Sprintf("path stops after %s (hop %d of %d tried)", lastSeen, lastHop(d.Path, lastSeen), len(d.Path)))
		default:
			parts = append(parts, "no router on the path answered")
		}
	} else if d.PathNote != "" {
		parts = append(parts, d.PathNote)
	}
	return strings.Join(parts, " · ")
}

func lastHop(path []proto.Hop, addr string) int {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i].Address == addr {
			return path[i].TTL
		}
	}
	return 0
}
