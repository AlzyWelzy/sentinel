package collect

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/AlzyWelzy/sentinel/netmon/snmp"
)

// IF-MIB columns.
const (
	ifDescr       = "1.3.6.1.2.1.2.2.1.2"
	ifType        = "1.3.6.1.2.1.2.2.1.3"
	ifMtu         = "1.3.6.1.2.1.2.2.1.4"
	ifSpeed       = "1.3.6.1.2.1.2.2.1.5"
	ifPhysAddress = "1.3.6.1.2.1.2.2.1.6"
	ifAdminStatus = "1.3.6.1.2.1.2.2.1.7"
	ifOperStatus  = "1.3.6.1.2.1.2.2.1.8"
	ifInOctets    = "1.3.6.1.2.1.2.2.1.10"
	ifInUcast     = "1.3.6.1.2.1.2.2.1.11"
	ifInDiscards  = "1.3.6.1.2.1.2.2.1.13"
	ifInErrors    = "1.3.6.1.2.1.2.2.1.14"
	ifOutOctets   = "1.3.6.1.2.1.2.2.1.16"
	ifOutUcast    = "1.3.6.1.2.1.2.2.1.17"
	ifOutDiscards = "1.3.6.1.2.1.2.2.1.19"
	ifOutErrors   = "1.3.6.1.2.1.2.2.1.20"
	ifName        = "1.3.6.1.2.1.31.1.1.1.1"
	ifHCInOctets  = "1.3.6.1.2.1.31.1.1.1.6"
	ifHCInUcast   = "1.3.6.1.2.1.31.1.1.1.7"
	ifHCInMcast   = "1.3.6.1.2.1.31.1.1.1.8"
	ifHCInBcast   = "1.3.6.1.2.1.31.1.1.1.9"
	ifHCOutOctets = "1.3.6.1.2.1.31.1.1.1.10"
	ifHCOutUcast  = "1.3.6.1.2.1.31.1.1.1.11"
	ifHCOutMcast  = "1.3.6.1.2.1.31.1.1.1.12"
	ifHCOutBcast  = "1.3.6.1.2.1.31.1.1.1.13"
	ifHighSpeed   = "1.3.6.1.2.1.31.1.1.1.15"
	ifAlias       = "1.3.6.1.2.1.31.1.1.1.18"
)

// counter pairs: metric name, 64-bit column, 32-bit fallback ("" = none).
var ifCounters = []struct{ name, hc, lc string }{
	{"if_in_octets", ifHCInOctets, ifInOctets},
	{"if_out_octets", ifHCOutOctets, ifOutOctets},
	{"if_in_unicast_packets", ifHCInUcast, ifInUcast},
	{"if_out_unicast_packets", ifHCOutUcast, ifOutUcast},
	{"if_in_multicast_packets", ifHCInMcast, ""},
	{"if_out_multicast_packets", ifHCOutMcast, ""},
	{"if_in_broadcast_packets", ifHCInBcast, ""},
	{"if_out_broadcast_packets", ifHCOutBcast, ""},
	{"if_in_errors", "", ifInErrors},
	{"if_out_errors", "", ifOutErrors},
	{"if_in_discards", "", ifInDiscards},
	{"if_out_discards", "", ifOutDiscards},
}

// interfaceNames returns ifIndex -> stable label name. ifName is preferred
// (it survives ifIndex renumbering on most platforms); ifDescr is the
// fallback. Duplicate names get "#<ifIndex>" appended so series never collide.
func (w *walker) interfaceNames(ctx context.Context) map[string]string {
	names := map[string]string{}
	for idx, p := range w.column(ctx, ifName) {
		if s := strings.TrimSpace(p.String()); s != "" {
			names[idx] = s
		}
	}
	descr := w.column(ctx, ifDescr)
	for idx, p := range descr {
		if _, ok := names[idx]; !ok {
			if s := strings.TrimSpace(p.String()); s != "" {
				names[idx] = s
			} else {
				names[idx] = "if" + idx
			}
		}
	}
	seen := map[string]int{}
	for _, n := range names {
		seen[n]++
	}
	for idx, n := range names {
		if seen[n] > 1 {
			names[idx] = fmt.Sprintf("%s#%s", n, idx)
		}
	}
	return names
}

func (w *walker) interfaces(ctx context.Context, opts Options) {
	names := w.interfaceNames(ctx)
	w.ifNames = names
	if len(names) == 0 {
		return
	}
	lbl := func(idx string) map[string]string { return map[string]string{"ifname": names[idx]} }

	oper := w.column(ctx, ifOperStatus)
	admin := w.column(ctx, ifAdminStatus)
	high := w.column(ctx, ifHighSpeed)
	low := w.column(ctx, ifSpeed)
	hcPresent := map[string]bool{}

	for _, c := range ifCounters {
		var hc map[string]snmp.PDU
		if c.hc != "" {
			hc = w.column(ctx, c.hc)
		}
		var lc map[string]snmp.PDU
		for idx := range names {
			if p, ok := hc[idx]; ok {
				w.r.add(c.name, lbl(idx), float64(p.Uint), true)
				if c.name == "if_in_octets" {
					hcPresent[idx] = true
				}
				continue
			}
			if c.lc == "" {
				continue
			}
			if lc == nil {
				lc = w.column(ctx, c.lc)
			}
			if p, ok := lc[idx]; ok {
				w.r.add(c.name, lbl(idx), float64(p.Uint), true)
			}
		}
	}
	w.lagMembers(ctx, names)
	for idx := range names {
		if p, ok := oper[idx]; ok {
			w.r.add("if_oper_status", lbl(idx), float64(p.Int), false)
		}
		if p, ok := admin[idx]; ok {
			w.r.add("if_admin_status", lbl(idx), float64(p.Int), false)
		}
		if sp := speedBps(high[idx], low[idx]); sp > 0 {
			w.r.add("if_speed_bps", lbl(idx), float64(sp), false)
		}
	}

	if !opts.Inventory {
		return
	}
	descr, alias := w.column(ctx, ifDescr), w.column(ctx, ifAlias)
	typ, mtu, mac := w.column(ctx, ifType), w.column(ctx, ifMtu), w.column(ctx, ifPhysAddress)
	for _, idx := range sortedKeysS(names) {
		it := Interface{
			Index:      atoi(idx),
			Name:       names[idx],
			Descr:      descr[idx].String(),
			Alias:      alias[idx].String(),
			Type:       int(typ[idx].Int),
			MTU:        int(mtu[idx].Int),
			SpeedBps:   speedBps(high[idx], low[idx]),
			AdminUp:    admin[idx].Int == 1,
			OperStatus: int(oper[idx].Int),
			HighCap:    hcPresent[idx],
		}
		if p, ok := mac[idx]; ok && len(p.Bytes) == 6 {
			it.MAC = net.HardwareAddr(p.Bytes).String()
		}
		w.r.Interfaces = append(w.r.Interfaces, it)
		w.r.add("if_info", map[string]string{"ifname": it.Name, "ifalias": it.Alias, "ifdescr": it.Descr, "iftype": fmt.Sprint(it.Type)}, 1, false)
	}
}

// speedBps prefers ifHighSpeed (Mbps) because ifSpeed saturates at 4.29 Gbps.
func speedBps(high, low snmp.PDU) uint64 {
	if high.Uint > 0 {
		return high.Uint * 1_000_000
	}
	return low.Uint
}

func sortedKeysS(m map[string]string) []string {
	pm := make(map[string]snmp.PDU, len(m))
	for k := range m {
		pm[k] = snmp.PDU{}
	}
	return sortedKeys(pm)
}

// ifStackStatus (IF-MIB ifStackTable): index = higher.lower ifIndex. A row
// whose both layers are real interfaces is a membership — on every vendor
// that's how port-channels / LAGs / bonds list their members.
const ifStackStatus = "1.3.6.1.2.1.31.1.2.1.3"

// lagMembers emits beacon_lag_member_info{lag, ifname} = 1 for each member
// of an aggregate, so alerts can join a member's status to its LAG.
func (w *walker) lagMembers(ctx context.Context, names map[string]string) {
	stack := w.column(ctx, ifStackStatus)
	// IEEE8023-LAG-MIB dot3adAggPortAttachedAggID: member ifIndex → its
	// aggregator's ifIndex (0 = not attached). Aruba lists LAGs only here.
	attached := w.column(ctx, "1.2.840.10006.300.43.1.2.1.1.13")
	if len(stack) == 0 && len(attached) == 0 {
		return
	}
	types := w.column(ctx, "1.3.6.1.2.1.2.2.1.3") // ifType
	seen := map[[2]string]bool{}
	emit := func(hi, lo string) {
		lag, member := names[hi], names[lo]
		if lag == "" || member == "" || hi == lo || seen[[2]string{hi, lo}] {
			return
		}
		if t, ok := types[hi]; !ok || t.Int != 161 {
			return
		}
		seen[[2]string{hi, lo}] = true
		w.r.add("lag_member_info", map[string]string{"lag": lag, "ifname": member}, 1, false)
	}
	for member, p := range attached {
		if p.Int > 0 {
			emit(strconv.FormatInt(p.Int, 10), member)
		}
	}
	for idx, p := range stack {
		if p.Int != 1 { // active(1) only
			continue
		}
		hi, lo, ok := strings.Cut(idx, ".")
		if !ok || hi == "0" || lo == "0" {
			continue
		}
		emit(hi, lo)
	}
}
