package main

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/AlzyWelzy/sentinel/proto"
)

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

type trapSink struct {
	mu  sync.Mutex
	got []proto.Trap
}

func (s *trapSink) add(b proto.Batch) {
	s.mu.Lock()
	s.got = append(s.got, b.Traps...)
	s.mu.Unlock()
}

func (s *trapSink) wait(t *testing.T, n int) []proto.Trap {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		if len(s.got) >= n {
			out := append([]proto.Trap(nil), s.got...)
			s.mu.Unlock()
			return out
		}
		s.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]proto.Trap(nil), s.got...)
}

func send(t *testing.T, g *gosnmp.GoSNMP, trap gosnmp.SnmpTrap) {
	t.Helper()
	if err := g.Connect(); err != nil {
		t.Fatal(err)
	}
	defer g.Conn.Close()
	if _, err := g.SendTrap(trap); err != nil {
		t.Fatal(err)
	}
}

func vpnDown() gosnmp.SnmpTrap {
	return gosnmp.SnmpTrap{Variables: []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(1000)},
		{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.12356.101.2.0.302"},
		{Name: ".1.3.6.1.4.1.12356.101.12.3.4.0", Type: gosnmp.OctetString, Value: []byte("to-branch")},
	}}
}

func TestTrapReceiver(t *testing.T) {
	port := freeUDPPort(t)
	t.Setenv("SENTINEL_TRAP_PORT", strconv.Itoa(port))
	sink := &trapSink{}
	r := newTrapReceiver(sink.add, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.set(ctx, []proto.NetworkDevice{
		{ID: "a", Address: "192.0.2.1", Credential: proto.SNMPCredential{Version: "2c", Community: "right"}},
		{ID: "b", Address: "192.0.2.2", Credential: proto.SNMPCredential{Version: "3", Username: "mon",
			AuthProtocol: "SHA256", AuthPassword: "authpass123", PrivProtocol: "AES", PrivPassword: "privpass123"}},
	})
	defer r.close()
	if r.Port() != port {
		t.Fatalf("port %d, want %d", r.Port(), port)
	}

	// v2c, right community: received, community not kept.
	send(t, &gosnmp.GoSNMP{Target: "127.0.0.1", Port: uint16(port), Version: gosnmp.Version2c, Community: "right", Timeout: time.Second}, vpnDown())
	// v2c, wrong community: dropped.
	send(t, &gosnmp.GoSNMP{Target: "127.0.0.1", Port: uint16(port), Version: gosnmp.Version2c, Community: "wrong", Timeout: time.Second}, vpnDown())
	// v1 enterprise trap from a FortiGate model OID.
	send(t, &gosnmp.GoSNMP{Target: "127.0.0.1", Port: uint16(port), Version: gosnmp.Version1, Community: "right", Timeout: time.Second},
		gosnmp.SnmpTrap{Enterprise: ".1.3.6.1.4.1.12356.101.1.1201", AgentAddress: "127.0.0.1", GenericTrap: 6, SpecificTrap: 301,
			Variables: []gosnmp.SnmpPDU{{Name: ".1.3.6.1.4.1.12356.101.12.3.4.0", Type: gosnmp.OctetString, Value: []byte("to-branch")}}})
	// v1 generic linkDown.
	send(t, &gosnmp.GoSNMP{Target: "127.0.0.1", Port: uint16(port), Version: gosnmp.Version1, Community: "right", Timeout: time.Second},
		gosnmp.SnmpTrap{Enterprise: ".1.3.6.1.4.1.30065", AgentAddress: "127.0.0.1", GenericTrap: 2,
			Variables: []gosnmp.SnmpPDU{{Name: ".1.3.6.1.2.1.2.2.1.1.5", Type: gosnmp.Integer, Value: 5}}})
	v3 := func(pass string) *gosnmp.GoSNMP {
		return &gosnmp.GoSNMP{Target: "127.0.0.1", Port: uint16(port), Version: gosnmp.Version3, Timeout: time.Second,
			SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.AuthPriv,
			SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: "mon", AuthoritativeEngineID: "8000000001020304",
				AuthenticationProtocol: gosnmp.SHA256, AuthenticationPassphrase: pass,
				PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: "privpass123"}}
	}
	// v3 with the right keys, then with a wrong auth password.
	send(t, v3("authpass123"), vpnDown())
	send(t, v3("wrongpass99"), vpnDown())

	got := sink.wait(t, 4)
	time.Sleep(trapFlushEvery + 500*time.Millisecond) // anything late (and wrong) would arrive now
	got = sink.wait(t, 99)
	if len(got) != 4 {
		t.Fatalf("got %d traps, want 4: %+v", len(got), got)
	}
	byVersion := map[string][]proto.Trap{}
	for _, tr := range got {
		byVersion[tr.Version] = append(byVersion[tr.Version], tr)
		if tr.Source != "127.0.0.1" {
			t.Errorf("source %q", tr.Source)
		}
		for k, v := range tr.Varbinds {
			if v == "right" || k == "1.3.6.1.6.3.18.1.4.0" {
				t.Errorf("community leaked: %s=%s", k, v)
			}
		}
	}
	if len(byVersion["2c"]) != 1 || byVersion["2c"][0].OID != "1.3.6.1.4.1.12356.101.2.0.302" ||
		byVersion["2c"][0].Varbinds["1.3.6.1.4.1.12356.101.12.3.4.0"] != "to-branch" {
		t.Errorf("v2c: %+v", byVersion["2c"])
	}
	v1 := map[string]bool{}
	for _, tr := range byVersion["1"] {
		v1[tr.OID] = true
	}
	if !v1["1.3.6.1.4.1.12356.101.1.1201.0.301"] || !v1["1.3.6.1.6.3.1.1.5.3"] {
		t.Errorf("v1 OIDs: %v", v1)
	}
	if len(byVersion["3"]) != 1 {
		t.Errorf("v3: %+v", byVersion["3"])
	}
}

func TestTrapReceiverOffWithoutSNMPDevices(t *testing.T) {
	t.Setenv("SENTINEL_TRAP_PORT", strconv.Itoa(freeUDPPort(t)))
	r := newTrapReceiver(func(proto.Batch) {}, nil)
	r.set(context.Background(), []proto.NetworkDevice{{ID: "pve", Credential: proto.SNMPCredential{Version: "proxmox"}}})
	if r.Port() != 0 {
		t.Fatal("must not listen without SNMP devices")
	}
}
