package main

// SNMP traps from the devices this agent polls. The receiver runs while the
// agent polls at least one SNMP device and accepts only traps that carry the
// community (v1, v2c) or the user and keys (v3) of one of those devices:
// anyone else's packets are dropped. Traps go into the spool like every
// other batch, so an ingest outage loses none; the credentials are never
// sent on.
//
// The standard port is UDP 162, which needs privilege: `install.sh --traps`
// gives the agent's service that one capability (CAP_NET_BIND_SERVICE).
// Without it the agent listens on 1162, for devices that can send to
// another port. SENTINEL_TRAP_PORT picks the port; 0 turns traps off.

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"

	"github.com/AlzyWelzy/sentinel/proto"
)

const (
	trapFlushEvery   = 2 * time.Second
	trapQueueMax     = 5000 // waiting for the next flush; more are dropped and counted
	trapFallbackPort = 1162
)

type trapCreds struct {
	communities map[string]bool
	users       []proto.SNMPCredential // v3
}

func (c trapCreds) key() string {
	var parts []string
	for k := range c.communities {
		parts = append(parts, "c:"+k)
	}
	for _, u := range c.users {
		parts = append(parts, "u:"+u.Username+"/"+u.AuthProtocol+"/"+u.AuthPassword+"/"+u.PrivProtocol+"/"+u.PrivPassword)
	}
	sort.Strings(parts)
	return strings.Join(parts, "\x00")
}

func credsFor(devices []proto.NetworkDevice) trapCreds {
	c := trapCreds{communities: map[string]bool{}}
	seen := map[string]bool{}
	for _, d := range devices {
		switch d.Credential.Version {
		case "1", "2c":
			if d.Credential.Community != "" {
				c.communities[d.Credential.Community] = true
			}
		case "3":
			k := d.Credential.Username + "\x00" + d.Credential.AuthPassword + "\x00" + d.Credential.PrivPassword
			if d.Credential.Username != "" && !seen[k] {
				seen[k] = true
				c.users = append(c.users, d.Credential)
			}
		}
	}
	return c
}

type trapReceiver struct {
	sink func(proto.Batch)
	log  *slog.Logger

	mu      sync.Mutex
	key     string
	creds   trapCreds
	ln      *gosnmp.TrapListener
	port    int
	queue   []proto.Trap
	dropped int
	stop    context.CancelFunc
}

func newTrapReceiver(sink func(proto.Batch), log *slog.Logger) *trapReceiver {
	if log == nil {
		log = slog.Default()
	}
	return &trapReceiver{sink: sink, log: log}
}

// Port is where traps are received, 0 when they aren't.
func (t *trapReceiver) Port() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.port
}

// set (re)starts the receiver for these devices' credentials, or stops it
// when there are none.
func (t *trapReceiver) set(ctx context.Context, devices []proto.NetworkDevice) {
	creds := credsFor(devices)
	key := creds.key()
	t.mu.Lock()
	if key == t.key && (t.ln != nil || key == "") {
		t.mu.Unlock()
		return
	}
	t.key, t.creds = key, creds
	old, oldStop := t.ln, t.stop
	t.ln, t.port, t.stop = nil, 0, nil
	t.mu.Unlock()
	if oldStop != nil {
		oldStop()
	}
	if old != nil {
		old.Close()
	}
	if key == "" {
		return
	}
	ports := []int{162, trapFallbackPort}
	if v, ok := os.LookupEnv("SENTINEL_TRAP_PORT"); ok {
		p, err := strconv.Atoi(v)
		if err != nil || p < 0 || p > 65535 {
			t.log.Error("SENTINEL_TRAP_PORT is not a port; traps are off", "value", v)
			return
		}
		if p == 0 {
			return
		}
		ports = []int{p}
	}
	for _, p := range ports {
		ln, err := t.listen(creds, p)
		if err != nil {
			t.log.Debug("trap port unavailable", "port", p, "err", err)
			continue
		}
		rctx, cancel := context.WithCancel(ctx)
		t.mu.Lock()
		t.ln, t.port, t.stop = ln, p, cancel
		t.mu.Unlock()
		go t.flushLoop(rctx)
		t.log.Info("receiving SNMP traps", "port", p)
		return
	}
	t.log.Warn("can't receive SNMP traps: no port available", "tried", ports)
}

func (t *trapReceiver) listen(creds trapCreds, port int) (*gosnmp.TrapListener, error) {
	ln := gosnmp.NewTrapListener()
	params := &gosnmp.GoSNMP{
		Port:      uint16(port),
		Transport: "udp",
		Version:   gosnmp.Version2c,
		Logger:    gosnmp.NewLogger(discard{}),
	}
	if len(creds.users) > 0 {
		table := gosnmp.NewSnmpV3SecurityParametersTable(gosnmp.NewLogger(discard{}))
		for _, u := range creds.users {
			sp := &gosnmp.UsmSecurityParameters{
				UserName:                 u.Username,
				AuthenticationProtocol:   authProto(u.AuthProtocol),
				AuthenticationPassphrase: u.AuthPassword,
				PrivacyProtocol:          privProto(u.PrivProtocol),
				PrivacyPassphrase:        u.PrivPassword,
			}
			if err := table.Add(u.Username, sp); err != nil {
				t.log.Warn("SNMPv3 trap user not usable", "user", u.Username, "err", err)
			}
		}
		// v3 authentication only runs on a v3 listener; v1 and v2c packets
		// are still read by their own version.
		params.Version = gosnmp.Version3
		params.SecurityModel = gosnmp.UserSecurityModel
		params.SetTrapSecurityParametersTable(table)
	}
	ln.Params = params
	ln.OnNewTrap = func(p *gosnmp.SnmpPacket, from *net.UDPAddr) { t.handle(p, from) }
	errc := make(chan error, 1)
	go func() { errc <- ln.Listen(net.JoinHostPort("0.0.0.0", strconv.Itoa(port))) }()
	select {
	case <-ln.Listening():
		return ln, nil
	case err := <-errc:
		if err == nil {
			err = fmt.Errorf("listener stopped")
		}
		return nil, err
	case <-time.After(3 * time.Second):
		ln.Close()
		return nil, fmt.Errorf("timed out starting the listener")
	}
}

type discard struct{}

func (discard) Print(...any)          {}
func (discard) Printf(string, ...any) {}

func authProto(s string) gosnmp.SnmpV3AuthProtocol {
	switch strings.ToUpper(s) {
	case "MD5":
		return gosnmp.MD5
	case "SHA", "SHA1":
		return gosnmp.SHA
	case "SHA224":
		return gosnmp.SHA224
	case "SHA256":
		return gosnmp.SHA256
	case "SHA384":
		return gosnmp.SHA384
	case "SHA512":
		return gosnmp.SHA512
	}
	return gosnmp.NoAuth
}

func privProto(s string) gosnmp.SnmpV3PrivProtocol {
	switch strings.ToUpper(s) {
	case "DES":
		return gosnmp.DES
	case "AES", "AES128":
		return gosnmp.AES
	case "AES192":
		return gosnmp.AES192
	case "AES256":
		return gosnmp.AES256
	case "AES192C":
		return gosnmp.AES192C
	case "AES256C":
		return gosnmp.AES256C
	}
	return gosnmp.NoPriv
}

// handle checks a trap's credentials and queues it.
func (t *trapReceiver) handle(p *gosnmp.SnmpPacket, from *net.UDPAddr) {
	t.mu.Lock()
	creds := t.creds
	t.mu.Unlock()
	var version string
	switch p.Version {
	case gosnmp.Version1:
		version = "1"
	case gosnmp.Version2c:
		version = "2c"
	case gosnmp.Version3:
		version = "3"
	}
	if version != "3" && !creds.communities[p.Community] {
		return // not one of our devices' communities
	}
	if version == "3" {
		// Unknown users and wrong keys fail in gosnmp's decoding; a packet
		// that reaches here without authentication is refused too.
		if p.MsgFlags&gosnmp.AuthNoPriv == 0 {
			return
		}
	}
	tr := proto.Trap{TimeMs: time.Now().UnixMilli(), Source: from.IP.String(), Version: version, Varbinds: map[string]string{}}
	if version == "1" {
		tr.OID = v1TrapOID(p)
	}
	for _, v := range p.Variables {
		name := strings.TrimPrefix(v.Name, ".")
		if name == "1.3.6.1.6.3.1.1.4.1.0" { // snmpTrapOID
			tr.OID = strings.TrimPrefix(fmt.Sprint(v.Value), ".")
			continue
		}
		if name == "1.3.6.1.6.3.18.1.4.0" { // snmpTrapCommunity
			continue
		}
		if len(tr.Varbinds) < 64 {
			tr.Varbinds[name] = varString(v)
		}
	}
	if tr.OID == "" {
		return
	}
	t.mu.Lock()
	if len(t.queue) >= trapQueueMax {
		t.dropped++
	} else {
		t.queue = append(t.queue, tr)
	}
	t.mu.Unlock()
}

// v1TrapOID converts an SNMPv1 trap to its v2 notification OID (RFC 3584
// section 3.1): generic traps are snmpTraps.<generic+1>, enterprise ones
// <enterprise>.0.<specific>.
func v1TrapOID(p *gosnmp.SnmpPacket) string {
	if p.GenericTrap >= 0 && p.GenericTrap < 6 {
		return "1.3.6.1.6.3.1.1.5." + strconv.Itoa(p.GenericTrap+1)
	}
	return strings.TrimPrefix(p.Enterprise, ".") + ".0." + strconv.Itoa(p.SpecificTrap)
}

func varString(v gosnmp.SnmpPDU) string {
	switch v.Type {
	case gosnmp.OctetString:
		b, _ := v.Value.([]byte)
		if utf8.Valid(b) && printable(b) {
			return cut(string(b), 512)
		}
		return hex.EncodeToString(b)
	case gosnmp.ObjectIdentifier:
		return strings.TrimPrefix(fmt.Sprint(v.Value), ".")
	case gosnmp.IPAddress:
		return fmt.Sprint(v.Value)
	}
	return cut(fmt.Sprint(v.Value), 512)
}

func printable(b []byte) bool {
	for _, r := range string(b) {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
	}
	return true
}

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// flushLoop sends queued traps to the spool every few seconds.
func (t *trapReceiver) flushLoop(ctx context.Context) {
	tick := time.NewTicker(trapFlushEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			t.flush()
			return
		case <-tick.C:
			t.flush()
		}
	}
}

func (t *trapReceiver) flush() {
	t.mu.Lock()
	q, dropped := t.queue, t.dropped
	t.queue, t.dropped = nil, 0
	t.mu.Unlock()
	if dropped > 0 {
		t.log.Warn("trap flood: dropped traps over the queue limit", "dropped", dropped)
	}
	if len(q) > 0 {
		t.sink(proto.Batch{TimestampMs: time.Now().UnixMilli(), Traps: q})
	}
}

// close stops receiving.
func (t *trapReceiver) close() {
	t.mu.Lock()
	ln, stop := t.ln, t.stop
	t.ln, t.port, t.stop, t.key = nil, 0, nil, ""
	t.mu.Unlock()
	if stop != nil {
		stop()
	}
	if ln != nil {
		ln.Close()
	}
	t.flush()
}
