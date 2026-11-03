package checks

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"
)

type publicOnlyKey struct{}

var errPrivateAddress = errors.New("private, loopback and link-local addresses can't be checked from public probes")

// dialer returns a dialer for a check. For probe checks it refuses any
// non-public address at connect time, after DNS resolution, so a hostname
// that resolves (or re-resolves) to an internal address is still blocked.
func dialer(ctx context.Context) *net.Dialer {
	d := &net.Dialer{Timeout: defaultTimeout, KeepAlive: -1 * time.Second}
	if v, _ := ctx.Value(publicOnlyKey{}).(bool); v {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				return err
			}
			if !publicAddress(ip) {
				return errPrivateAddress
			}
			return nil
		}
	}
	return d
}

// Ranges that aren't the public internet beyond what netip classifies.
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),  // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking
	netip.MustParsePrefix("0.0.0.0/8"),      // "this network"
	netip.MustParsePrefix("240.0.0.0/4"),    // reserved
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64
	netip.MustParsePrefix("2001:db8::/32"),  // documentation
}

// nat64 is the well-known NAT64 prefix: an address in it reaches the IPv4
// address in its last 32 bits, so it's judged by that one.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

func publicAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if nat64.Contains(ip) {
		b := ip.As16()
		ip = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
