package collect

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/AlzyWelzy/sentinel/netmon/snmp"
)

// Forwarding (MAC) and ARP tables, for IPDR: which MAC was on which port,
// and which IP it had. Q-BRIDGE (per VLAN) first, the plain BRIDGE table
// when a switch has no Q-BRIDGE; ARP from both the old IPv4 table and the
// newer IP-MIB one (IPv6 too).
const (
	dot1qTpFdbPort         = "1.3.6.1.2.1.17.7.1.2.2.1.2"
	dot1dTpFdbPort         = "1.3.6.1.2.1.17.4.3.1.2"
	dot1dBasePortIfIndex   = "1.3.6.1.2.1.17.1.4.1.2"
	ifNameOID              = "1.3.6.1.2.1.31.1.1.1.1"
	ipNetToMediaPhysAddr   = "1.3.6.1.2.1.4.22.1.2"
	ipNetToPhysicalPhysAdr = "1.3.6.1.2.1.4.35.1.4"
	maxFDBRows             = 200_000
)

// FDBRow is one MAC table or ARP row.
type FDBRow struct {
	Port    string
	IfIndex uint32
	VLAN    uint16
	MAC     string
	IP      string
	Source  string // fdb, arp
}

func walkColumn(ctx context.Context, s snmp.Session, oid string) (map[string]snmp.PDU, error) {
	m := map[string]snmp.PDU{}
	err := s.Walk(ctx, oid, func(p snmp.PDU) error {
		if len(m) >= maxFDBRows {
			return fmt.Errorf("more than %d rows", maxFDBRows)
		}
		if idx := snmp.Suffix(p.OID, oid); idx != "" {
			m[idx] = p
		}
		return nil
	})
	return m, err
}

// macFromIndex reads six dotted decimals as a MAC.
func macFromIndex(parts []string) (string, bool) {
	if len(parts) != 6 {
		return "", false
	}
	b := make([]string, 6)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return "", false
		}
		b[i] = fmt.Sprintf("%02x", n)
	}
	return strings.Join(b, ":"), true
}

func macFromBytes(v []byte) (string, bool) {
	if len(v) != 6 {
		return "", false
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", v[0], v[1], v[2], v[3], v[4], v[5]), true
}

func pduInt(p snmp.PDU) int64 {
	if p.Kind == snmp.KindInteger {
		return p.Int
	}
	return int64(p.Uint)
}

// FDB reads a device's MAC and ARP tables. Errors from tables a device
// doesn't have are expected; the error returned is only for when nothing
// could be read at all.
func FDB(ctx context.Context, s snmp.Session) ([]FDBRow, error) {
	names := map[uint32]string{}
	if col, err := walkColumn(ctx, s, ifNameOID); err == nil {
		for idx, p := range col {
			if n, err := strconv.ParseUint(idx, 10, 32); err == nil {
				names[uint32(n)] = string(p.Bytes)
			}
		}
	}
	bridge := map[int64]uint32{}
	if col, err := walkColumn(ctx, s, dot1dBasePortIfIndex); err == nil {
		for idx, p := range col {
			if n, err := strconv.ParseInt(idx, 10, 64); err == nil {
				bridge[n] = uint32(pduInt(p))
			}
		}
	}
	var out []FDBRow
	add := func(port int64, vlan uint16, mac string) {
		ifx := bridge[port]
		if ifx == 0 && port > 0 {
			ifx = uint32(port) // some switches use ifIndex as the bridge port
		}
		out = append(out, FDBRow{Port: names[ifx], IfIndex: ifx, VLAN: vlan, MAC: mac, Source: "fdb"})
	}
	var firstErr error
	q, err := walkColumn(ctx, s, dot1qTpFdbPort)
	if err != nil {
		firstErr = err
	}
	for idx, p := range q {
		parts := strings.Split(idx, ".")
		if len(parts) != 7 {
			continue
		}
		vlan, _ := strconv.ParseUint(parts[0], 10, 16)
		if mac, ok := macFromIndex(parts[1:]); ok && pduInt(p) > 0 {
			add(pduInt(p), uint16(vlan), mac)
		}
	}
	if len(q) == 0 {
		d, err := walkColumn(ctx, s, dot1dTpFdbPort)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		for idx, p := range d {
			if mac, ok := macFromIndex(strings.Split(idx, ".")); ok && pduInt(p) > 0 {
				add(pduInt(p), 0, mac)
			}
		}
	}
	seenARP := map[string]bool{}
	arp := func(ifx uint32, ip netip.Addr, macB []byte) {
		mac, ok := macFromBytes(macB)
		if !ok || mac == "00:00:00:00:00:00" || !ip.IsValid() {
			return
		}
		k := ip.String() + "/" + mac
		if seenARP[k] {
			return
		}
		seenARP[k] = true
		out = append(out, FDBRow{Port: names[ifx], IfIndex: ifx, MAC: mac, IP: ip.String(), Source: "arp"})
	}
	if col, err := walkColumn(ctx, s, ipNetToPhysicalPhysAdr); err == nil {
		// Index: ifIndex.addrType.len.addr…
		for idx, p := range col {
			parts := strings.Split(idx, ".")
			if len(parts) < 4 {
				continue
			}
			ifx, _ := strconv.ParseUint(parts[0], 10, 32)
			n, _ := strconv.Atoi(parts[2])
			if n != len(parts)-3 || (n != 4 && n != 16) {
				continue
			}
			raw := make([]byte, n)
			for i, v := range parts[3:] {
				b, err := strconv.Atoi(v)
				if err != nil || b < 0 || b > 255 {
					raw = nil
					break
				}
				raw[i] = byte(b)
			}
			if a, ok := netip.AddrFromSlice(raw); ok {
				arp(uint32(ifx), a.Unmap(), p.Bytes)
			}
		}
	}
	if col, err := walkColumn(ctx, s, ipNetToMediaPhysAddr); err == nil {
		// Index: ifIndex.a.b.c.d
		for idx, p := range col {
			parts := strings.SplitN(idx, ".", 2)
			if len(parts) != 2 {
				continue
			}
			ifx, _ := strconv.ParseUint(parts[0], 10, 32)
			if a, err := netip.ParseAddr(parts[1]); err == nil {
				arp(uint32(ifx), a, p.Bytes)
			}
		}
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}
