package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/AlzyWelzy/sentinel/netmon/snmp"
)

const fdbWalk = `.1.3.6.1.2.1.31.1.1.1.1.7 = STRING: "Ethernet7"
.1.3.6.1.2.1.31.1.1.1.1.9 = STRING: "Vlan10"
.1.3.6.1.2.1.17.1.4.1.2.3 = INTEGER: 7
.1.3.6.1.2.1.17.7.1.2.2.1.2.10.0.28.115.1.2.3 = INTEGER: 3
.1.3.6.1.2.1.17.7.1.2.2.1.2.10.0.28.115.1.2.4 = INTEGER: 0
.1.3.6.1.2.1.4.22.1.2.9.10.0.0.5 = Hex-STRING: 00 1C 73 01 02 03
.1.3.6.1.2.1.4.35.1.4.9.1.4.10.0.0.5 = Hex-STRING: 00 1C 73 01 02 03
.1.3.6.1.2.1.4.35.1.4.9.2.16.254.128.0.0.0.0.0.0.2.28.115.255.254.1.2.3 = Hex-STRING: 00 1C 73 01 02 03
.1.3.6.1.2.1.4.22.1.2.9.10.0.0.6 = Hex-STRING: 00 00 00 00 00 00
`

func TestFDB(t *testing.T) {
	s, err := snmp.ParseWalk(strings.NewReader(fdbWalk))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := FDB(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	var fdb, arp []FDBRow
	for _, r := range rows {
		if r.Source == "fdb" {
			fdb = append(fdb, r)
		} else {
			arp = append(arp, r)
		}
	}
	if len(fdb) != 1 || fdb[0].MAC != "00:1c:73:01:02:03" || fdb[0].Port != "Ethernet7" || fdb[0].VLAN != 10 || fdb[0].IfIndex != 7 {
		t.Fatalf("fdb: %+v", fdb)
	}
	// The same IPv4 from both ARP tables once, plus the IPv6 neighbour.
	if len(arp) != 2 {
		t.Fatalf("arp: %+v", arp)
	}
	ips := arp[0].IP + " " + arp[1].IP
	if !strings.Contains(ips, "10.0.0.5") || !strings.Contains(ips, "fe80::21c:73ff:fe01:203") || arp[0].Port != "Vlan10" {
		t.Fatalf("arp: %+v", arp)
	}
}
