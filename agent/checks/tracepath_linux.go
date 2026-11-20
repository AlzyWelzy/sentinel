//go:build linux

package checks

import (
	"context"
	"encoding/binary"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"

	"github.com/AlzyWelzy/sentinel/proto"
)

// tracePath finds the routers towards ip the way tracepath does, without
// privileges: UDP probes with a rising TTL on a socket with IP_RECVERR, so
// each router's "time exceeded" (and the destination's "port unreachable")
// comes back on the error queue. IPv4 and IPv6.
func tracePath(ctx context.Context, ip netip.Addr, max int) ([]proto.Hop, string) {
	v6 := ip.Is6()
	family, level, ttlOpt, errOpt := unix.AF_INET, unix.IPPROTO_IP, unix.IP_TTL, unix.IP_RECVERR
	if v6 {
		family, level, ttlOpt, errOpt = unix.AF_INET6, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, unix.IPV6_RECVERR
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return nil, "path tracing unavailable: " + err.Error()
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, level, errOpt, 1); err != nil {
		return nil, "path tracing unavailable: " + err.Error()
	}
	var hops []proto.Hop
	for ttl := 1; ttl <= max; ttl++ {
		if ctx.Err() != nil {
			break
		}
		if err := unix.SetsockoptInt(fd, level, ttlOpt, ttl); err != nil {
			return hops, "path tracing stopped: " + err.Error()
		}
		port := 33434 + ttl
		var sa unix.Sockaddr
		if v6 {
			sa = &unix.SockaddrInet6{Port: port, Addr: ip.As16()}
		} else {
			sa = &unix.SockaddrInet4{Port: port, Addr: ip.As4()}
		}
		start := time.Now()
		if err := unix.Sendto(fd, []byte("sentinel"), 0, sa); err != nil {
			// Some kernels report the previous hop's error on send: read it.
			_ = err
		}
		hop := proto.Hop{TTL: ttl}
		deadline := start.Add(time.Second)
		for time.Now().Before(deadline) {
			from, reached, got := readErrQueue(fd, v6, time.Until(deadline))
			if !got {
				break
			}
			hop.Address, hop.Reached = from, reached
			hop.RttMs = ms(time.Since(start))
			break
		}
		hops = append(hops, hop)
		if hop.Reached {
			break
		}
		// Three silent routers in a row at the end: the path is dark.
		if n := len(hops); n >= 6 && hops[n-1].Address == "" && hops[n-2].Address == "" && hops[n-3].Address == "" {
			break
		}
	}
	return hops, ""
}

// readErrQueue waits for one ICMP error and returns who sent it, and whether
// it came from the destination itself (port unreachable).
func readErrQueue(fd int, v6 bool, wait time.Duration) (string, bool, bool) {
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLERR | unix.POLLIN}}
	n, err := unix.Poll(pfd, int(wait.Milliseconds())+1)
	if err != nil || n == 0 {
		return "", false, false
	}
	buf := make([]byte, 512)
	oob := make([]byte, 512)
	_, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
	if err != nil {
		return "", false, false
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return "", false, false
	}
	for _, m := range msgs {
		// struct sock_extended_err (16 bytes) then the offender's sockaddr.
		if len(m.Data) < 16 {
			continue
		}
		origin, typ, code := m.Data[4], m.Data[5], m.Data[6]
		offender := m.Data[16:]
		var addr netip.Addr
		if !v6 && len(offender) >= 8 && binary.LittleEndian.Uint16(offender[0:2]) == unix.AF_INET {
			addr = netip.AddrFrom4([4]byte(offender[4:8]))
		} else if v6 && len(offender) >= 24 && binary.LittleEndian.Uint16(offender[0:2]) == unix.AF_INET6 {
			addr = netip.AddrFrom16([16]byte(offender[8:24]))
		}
		// "Port unreachable" comes from the destination itself: the path
		// works up to the server. Any other reply is a router on the way.
		reached := (!v6 && origin == unix.SO_EE_ORIGIN_ICMP && typ == 3 && code == 3) ||
			(v6 && origin == unix.SO_EE_ORIGIN_ICMP6 && typ == 1 && code == 4)
		if addr.IsValid() {
			return addr.String(), reached, true
		}
	}
	return "", false, false
}
