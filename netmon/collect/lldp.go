package collect

import (
	"context"
	"net"
	"strconv"
	"strings"

	"github.com/AlzyWelzy/pulsegrid-beyond/netmon/snmp"
)

// LLDP-MIB (IEEE 802.1AB-2005) columns.
const (
	lldpLocPortID     = "1.0.8802.1.1.2.1.3.7.1.3"
	lldpLocPortDesc   = "1.0.8802.1.1.2.1.3.7.1.4"
	lldpRemChassisSub = "1.0.8802.1.1.2.1.4.1.1.4"
	lldpRemChassisID  = "1.0.8802.1.1.2.1.4.1.1.5"
	lldpRemPortIDSub  = "1.0.8802.1.1.2.1.4.1.1.6"
	lldpRemPortID     = "1.0.8802.1.1.2.1.4.1.1.7"
	lldpRemPortDesc   = "1.0.8802.1.1.2.1.4.1.1.8"
	lldpRemSysName    = "1.0.8802.1.1.2.1.4.1.1.9"
	lldpRemManAddrIf  = "1.0.8802.1.1.2.1.4.2.1.3"
)

// lldp decodes the remote table. Index = timeMark.localPortNum.remIndex.
func (w *walker) lldp(ctx context.Context) {
	sysNames := w.column(ctx, lldpRemSysName)
	chassis := w.column(ctx, lldpRemChassisID)
	if len(sysNames) == 0 && len(chassis) == 0 {
		return
	}
	portIDs := w.column(ctx, lldpRemPortID)
	portSub := w.column(ctx, lldpRemPortIDSub)
	portDescs := w.column(ctx, lldpRemPortDesc)
	chassisSub := w.column(ctx, lldpRemChassisSub)
	locIDs := w.column(ctx, lldpLocPortID)
	locDescs := w.column(ctx, lldpLocPortDesc)

	ifNames := map[string]bool{}
	for _, it := range w.r.Interfaces {
		ifNames[it.Name] = true
		ifNames[it.Descr] = true
	}
	localName := func(port string) string {
		id, desc := strings.TrimSpace(locIDs[port].String()), strings.TrimSpace(locDescs[port].String())
		switch {
		case id != "" && ifNames[id]:
			return id
		case desc != "" && ifNames[desc]:
			return desc
		case desc != "":
			return desc
		case id != "":
			return id
		}
		// Agents without lldpLocPortTable (FortiGate) number LLDP ports by ifIndex.
		if n, ok := w.ifNames[port]; ok {
			return n
		}
		return "port" + port
	}

	mgmt := map[string]string{}
	_ = w.s.Walk(ctx, lldpRemManAddrIf, func(p snmp.PDU) error {
		// suffix: timeMark.localPort.remIndex.addrSubtype.addrLen.a.b.c.d
		parts := strings.Split(snmp.Suffix(p.OID, lldpRemManAddrIf), ".")
		if len(parts) >= 9 && parts[3] == "1" && parts[4] == "4" {
			key := strings.Join(parts[:3], ".")
			if _, ok := mgmt[key]; !ok {
				mgmt[key] = strings.Join(parts[5:9], ".")
			}
		}
		return nil
	})

	keys := map[string]bool{}
	for k := range sysNames {
		keys[k] = true
	}
	for k := range chassis {
		keys[k] = true
	}
	for _, idx := range sortedKeysS(boolKeys(keys)) {
		parts := strings.Split(idx, ".")
		if len(parts) != 3 {
			continue
		}
		n := Neighbor{
			LocalPort:      localName(parts[1]),
			RemoteSysName:  strings.TrimSpace(sysNames[idx].String()),
			RemotePortID:   decodeID(portIDs[idx], int(portSub[idx].Int)),
			RemotePortDesc: strings.TrimSpace(portDescs[idx].String()),
			RemoteChassis:  decodeID(chassis[idx], int(chassisSub[idx].Int)),
			RemoteMgmtAddr: mgmt[idx],
		}
		w.r.Neighbors = append(w.r.Neighbors, n)
	}
}

// decodeID renders chassis/port IDs: MAC subtypes (chassis 4, port 3) as MAC,
// network-address subtype (5/4) as IP when possible, otherwise as text.
func decodeID(p snmp.PDU, subtype int) string {
	b := p.Bytes
	if len(b) == 6 && (subtype == 4 || subtype == 3) {
		return net.HardwareAddr(b).String()
	}
	if len(b) == 5 && b[0] == 1 && (subtype == 5 || subtype == 4) {
		return net.IP(b[1:]).String()
	}
	return strings.TrimSpace(p.String())
}

func boolKeys(m map[string]bool) map[string]string {
	out := make(map[string]string, len(m))
	for k := range m {
		out[k] = strconv.Itoa(len(k))
	}
	return out
}
