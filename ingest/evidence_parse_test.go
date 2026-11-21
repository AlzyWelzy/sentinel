package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/AlzyWelzy/sentinel/proto"
)

const fortiTraffic = `<189>date=2026-11-21 time=10:15:02 devname="FG-EDGE" devid="FG100F" eventtime=1795255502123456789 tz="+0530" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.0.0.5 srcport=51000 srcintf="lan" srcmac="AA:BB:CC:00:11:22" dstip=93.184.216.34 dstport=443 dstintf="wan1" sessionid=778899 proto=6 action="accept" policyid=12 service="HTTPS" transip=203.0.113.9 transport=40001 duration=31 sentbyte=1200 rcvdbyte=56000 app="Web Browsing" user="ada"`

func TestParseFortiAndSyslog(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	p := parseLog(fortiTraffic, now)
	if p.KV["type"] != "traffic" || p.KV["devname"] != "FG-EDGE" || p.KV["app"] != "Web Browsing" || !p.Parsed {
		t.Fatalf("forti: %+v", p.KV)
	}
	if p.EventTime.Unix() != 1795255502 {
		t.Fatalf("eventtime: %v", p.EventTime)
	}
	p = parseLog(`<34>1 2026-11-21T10:00:00.5Z core1 sshd 123 ID47 - Failed password for root from 198.51.100.7 port 4022`, now)
	if !p.Parsed || p.Hostname != "core1" || p.Program != "sshd" || p.Facility != 4 || p.Severity != 2 || len(p.IPs) != 1 {
		t.Fatalf("5424: %+v", p)
	}
	p = parseLog(`<13>Nov 21 09:00:01 sw-2 %LINK-3-UPDOWN: Interface Ethernet7, changed state to down`, now)
	if !p.Parsed || p.Hostname != "sw-2" || p.Program != "%LINK-3-UPDOWN" || p.EventTime.Hour() != 9 {
		t.Fatalf("3164: %+v", p)
	}
	p = parseLog("garbage with 2001:db8::1 and 10.1.2.3 inside", now)
	if p.Parsed || len(p.IPs) != 2 {
		t.Fatalf("unparsed: %+v", p)
	}
}

func TestBuildEvidenceRows(t *testing.T) {
	at := time.Now().UTC()
	vpn := `<189>logid="0101039947" type="event" subtype="vpn" devname="FG-EDGE" action="tunnel-up" user="grace" remip=198.51.100.20 tunnelip=10.212.134.200`
	b := proto.EvidenceBatch{
		Logs:  []proto.LogRecord{{At: at, Src: "192.0.2.1", Line: fortiTraffic}, {At: at, Src: "192.0.2.1", Line: vpn}, {At: at, Src: "192.0.2.9", Line: "<13>hello"}},
		Flows: []proto.FlowRecord{{At: at, Exporter: "192.0.2.1", Type: "ipfix", SrcIP: "10.0.0.5", DstIP: "1.1.1.1", Bytes: 9}},
		FDB:   []proto.FDBEntry{{At: at, DeviceID: "dev-a", MAC: "AA:BB:CC:00:11:22", IP: "10.0.0.5", Source: "arp"}, {At: at, DeviceID: "other", MAC: "x"}},
	}
	dev := map[netip.Addr]string{netip.MustParseAddr("192.0.2.1"): "dev-a"}
	rows := buildEvidenceRows("t1", "2027-01-01", b, dev, func(d string) bool { return d == "dev-a" })
	if len(rows["fw_sessions"]) != 1 || len(rows["syslog"]) != 2 || len(rows["ip_users"]) != 1 || len(rows["flows"]) != 1 || len(rows["mac_table"]) != 1 {
		t.Fatalf("tables: %v", map[string]int{"fw": len(rows["fw_sessions"]), "syslog": len(rows["syslog"]), "ipu": len(rows["ip_users"]), "flows": len(rows["flows"]), "mac": len(rows["mac_table"])})
	}
	fw := rows["fw_sessions"][0]
	if fw["device_id"] != "dev-a" || fw["src_ip"] != "::ffff:10.0.0.5" || fw["nat_src_ip"] != "::ffff:203.0.113.9" || fw["rcvd_bytes"] != uint64(56000) || fw["src_mac"] != "aa:bb:cc:00:11:22" || fw["tenant_id"] != "t1" {
		t.Fatalf("fw row: %v", fw)
	}
	if u := rows["ip_users"][0]; u["ip"] != "::ffff:10.212.134.200" || u["user"] != "grace" {
		t.Fatalf("identity: %v", u)
	}
	if rows["mac_table"][0]["mac"] != "aa:bb:cc:00:11:22" {
		t.Fatal(rows["mac_table"][0])
	}
}
