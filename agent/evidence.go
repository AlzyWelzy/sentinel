package main

// IPDR evidence receivers: syslog (UDP and TCP), sFlow, NetFlow v5/v9 and
// IPFIX, plus MAC/ARP table snapshots of the devices this agent polls.
// They run only on the server an organisation picked as its evidence
// collector, with the ports its config names.
//
// Only senders this agent polls (or the organisation's allowed ranges) are
// accepted: anyone else on the network could otherwise write evidence.
// Records are batched every 2 s into their own disk spool and delivered
// oldest first to ingest's /v1/evidence. The spool never drops what it has:
// when it's full, TCP senders are paused and UDP datagrams are counted as
// dropped (UDP can't wait, which is why firewalls should log over TCP).

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	flowpb "github.com/netsampler/goflow2/v2/pb"
	protoproducer "github.com/netsampler/goflow2/v2/producer/proto"
	"github.com/netsampler/goflow2/v2/utils"

	"github.com/AlzyWelzy/sentinel/netmon/collect"
	"github.com/AlzyWelzy/sentinel/netmon/snmp"
	"github.com/AlzyWelzy/sentinel/proto"
)

const (
	evidenceMaxLine      = 64 << 10
	evidenceBatchItems   = 5000
	evidenceFlushEvery   = 2 * time.Second
	evidenceSpoolDefault = 20 << 30 // 20 GiB; SENTINEL_EVIDENCE_SPOOL_GB overrides
	evidenceUDPBuffer    = 16 << 20
)

type evidence struct {
	log      *slog.Logger
	dir      string
	maxBytes int64
	deliver  func(ctx context.Context, b proto.EvidenceBatch) error

	mu        sync.Mutex
	cfg       proto.EvidenceConfig
	devices   []proto.NetworkDevice
	allowed   map[netip.Addr]bool
	nets      []netip.Prefix
	cancel    context.CancelFunc
	listening []string
	cfgKey    string

	in                                 chan any
	dropped, refused, flowErrs, queued atomic.Uint64
	spoolBytes                         atomic.Int64
}

func newEvidence(stateDir string, log *slog.Logger, deliver func(context.Context, proto.EvidenceBatch) error) (*evidence, error) {
	dir := filepath.Join(stateDir, "evidence-spool")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if tmps, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(tmps) > 0 {
		for _, t := range tmps {
			os.Remove(t)
		}
	}
	max := int64(evidenceSpoolDefault)
	if gb, err := strconv.Atoi(os.Getenv("SENTINEL_EVIDENCE_SPOOL_GB")); err == nil && gb > 0 {
		max = int64(gb) << 30
	}
	e := &evidence{log: log, dir: dir, maxBytes: max, deliver: deliver, in: make(chan any, 65536)}
	e.spoolBytes.Store(e.measure())
	return e, nil
}

func (e *evidence) measure() int64 {
	var n int64
	names, _ := filepath.Glob(filepath.Join(e.dir, "*.json"))
	for _, name := range names {
		if fi, err := os.Stat(name); err == nil {
			n += fi.Size()
		}
	}
	return n
}

func (e *evidence) full() bool { return e.spoolBytes.Load() >= e.maxBytes }

// set applies the config (nil: off) and the devices this agent polls.
func (e *evidence) set(ctx context.Context, cfg *proto.EvidenceConfig, devices []proto.NetworkDevice) {
	e.mu.Lock()
	e.devices = devices
	e.allowed = map[netip.Addr]bool{}
	for _, d := range devices {
		host := d.Address
		if h, _, err := net.SplitHostPort(d.Address); err == nil {
			host = h
		}
		if a, err := netip.ParseAddr(host); err == nil {
			e.allowed[a.Unmap()] = true
		} else if ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host); err == nil {
			for _, a := range ips {
				e.allowed[a.Unmap()] = true
			}
		}
	}
	e.nets = nil
	if cfg != nil {
		for _, c := range cfg.Allow {
			if p, err := netip.ParsePrefix(c); err == nil {
				e.nets = append(e.nets, p.Masked())
			} else if a, err := netip.ParseAddr(c); err == nil {
				e.nets = append(e.nets, netip.PrefixFrom(a, a.BitLen()))
			}
		}
	}
	key := ""
	if cfg != nil {
		b, _ := json.Marshal(struct {
			U, T, S, N, I, F int
		}{cfg.SyslogUDP, cfg.SyslogTCP, cfg.SFlow, cfg.NetFlow, cfg.IPFIX, cfg.FDBIntervalSeconds})
		key = string(b)
	}
	if key == e.cfgKey {
		e.mu.Unlock()
		return
	}
	if e.cancel != nil {
		e.cancel()
		e.cancel = nil
	}
	e.cfgKey, e.listening = key, nil
	if cfg == nil {
		e.mu.Unlock()
		return
	}
	e.cfg = *cfg
	rctx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	e.mu.Unlock()
	// Listeners register themselves under the lock, so start them after it.
	// The standard syslog ports first (514 UDP, 601 TCP) when the service
	// may bind them (install.sh --evidence), the configured ones otherwise.
	std := os.Getenv("SENTINEL_EVIDENCE_STANDARD_PORTS") != "0"
	if cfg.SyslogUDP > 0 {
		if !std || !e.listenSyslogUDP(rctx, 514, false) {
			e.listenSyslogUDP(rctx, cfg.SyslogUDP, true)
		}
	}
	if cfg.SyslogTCP > 0 {
		if !std || !e.listenSyslogTCP(rctx, 601, false) {
			e.listenSyslogTCP(rctx, cfg.SyslogTCP, true)
		}
	}
	for _, l := range []struct {
		port int
		kind string
	}{{cfg.SFlow, "sflow"}, {cfg.NetFlow, "netflow"}, {cfg.IPFIX, "ipfix"}} {
		if l.port > 0 {
			e.listenFlows(rctx, l.port, l.kind)
		}
	}
	if cfg.FDBIntervalSeconds > 0 {
		go e.fdbLoop(rctx, time.Duration(cfg.FDBIntervalSeconds)*time.Second)
	}
}

// start runs the batcher and the delivery loop for the agent's lifetime;
// spooled evidence is delivered even while the receivers are off.
func (e *evidence) start(ctx context.Context) {
	go e.batcher(ctx)
	go e.replay(ctx)
}

func (e *evidence) accept(a netip.Addr) bool {
	a = a.Unmap()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.allowed[a] {
		return true
	}
	for _, p := range e.nets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (e *evidence) addListener(s string) {
	e.mu.Lock()
	e.listening = append(e.listening, s)
	e.mu.Unlock()
	e.log.Info("evidence receiver listening", "on", s)
}

func addrOf(a net.Addr) netip.Addr {
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

func (e *evidence) listenSyslogUDP(ctx context.Context, port int, report bool) bool {
	pc, err := net.ListenPacket("udp", ":"+strconv.Itoa(port))
	if err != nil {
		if report {
			e.log.Error("syslog udp listen failed", "port", port, "err", err)
		}
		return false
	}
	if uc, ok := pc.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(evidenceUDPBuffer)
	}
	e.addListener(fmt.Sprintf("syslog/udp %d", port))
	go func() { <-ctx.Done(); pc.Close() }()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			src := addrOf(from)
			if !e.accept(src) {
				e.refused.Add(1)
				continue
			}
			if e.full() {
				e.dropped.Add(1)
				continue
			}
			for _, l := range strings.Split(string(buf[:n]), "\n") {
				e.addLine(src, "udp", l)
			}
		}
	}()
	return true
}

func (e *evidence) listenSyslogTCP(ctx context.Context, port int, report bool) bool {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		if report {
			e.log.Error("syslog tcp listen failed", "port", port, "err", err)
		}
		return false
	}
	e.addListener(fmt.Sprintf("syslog/tcp %d", port))
	go func() { <-ctx.Done(); ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
			src := addrOf(conn.RemoteAddr())
			if !e.accept(src) {
				e.refused.Add(1)
				conn.Close()
				continue
			}
			go e.serveTCP(ctx, conn, src)
		}
	}()
	return true
}

// serveTCP reads one stream in either RFC 6587 framing: octet counting
// ("<len> <msg>", FortiGate's reliable mode) or LF-terminated lines.
func (e *evidence) serveTCP(ctx context.Context, conn net.Conn, src netip.Addr) {
	defer conn.Close()
	go func() { <-ctx.Done(); conn.Close() }()
	r := bufio.NewReaderSize(conn, 256<<10)
	for ctx.Err() == nil {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Minute))
		for e.full() { // back-pressure: stop reading until the spool drains
			if ctx.Err() != nil {
				return
			}
			time.Sleep(time.Second)
		}
		line, err := readFrame(r)
		if line != "" {
			e.addLine(src, "tcp", line)
		}
		if err != nil {
			return
		}
	}
}

func readFrame(r *bufio.Reader) (string, error) {
	b, err := r.Peek(1)
	if err != nil {
		return "", err
	}
	if b[0] >= '1' && b[0] <= '9' {
		lenStr, err := r.ReadString(' ')
		if err != nil {
			return lenStr, err
		}
		n, convErr := strconv.Atoi(strings.TrimSpace(lenStr))
		if convErr != nil || n <= 0 || n > 16<<20 {
			rest, err := r.ReadString('\n')
			return lenStr + rest, err
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return string(buf), err
		}
		return string(buf), nil
	}
	return r.ReadString('\n')
}

func (e *evidence) addLine(src netip.Addr, proto_, line string) {
	line = strings.TrimRight(line, "\r\n\x00")
	if strings.TrimSpace(line) == "" {
		return
	}
	if len(line) > evidenceMaxLine {
		line = line[:evidenceMaxLine]
	}
	e.in <- proto.LogRecord{At: time.Now().UTC(), Src: src.String(), Proto: proto_, Line: line}
}

// flowSink receives goflow2's decoded messages.
type flowSink struct{ e *evidence }

func (f flowSink) Format(data any) ([]byte, []byte, error) {
	if m, ok := data.(*protoproducer.ProtoProducerMessage); ok {
		f.e.in <- flowRecord(&m.FlowMessage)
	}
	return nil, nil, nil
}

func flowRecord(m *flowpb.FlowMessage) proto.FlowRecord {
	kind := map[flowpb.FlowMessage_FlowType]string{
		flowpb.FlowMessage_SFLOW_5: "sflow", flowpb.FlowMessage_NETFLOW_V5: "netflow5",
		flowpb.FlowMessage_NETFLOW_V9: "netflow9", flowpb.FlowMessage_IPFIX: "ipfix",
	}[m.Type]
	r := proto.FlowRecord{
		At: time.Unix(0, int64(m.TimeReceivedNs)).UTC(), Exporter: ipString(m.SamplerAddress), Type: kind,
		Sampling: uint32(m.SamplingRate), Proto: uint8(m.Proto), SrcIP: ipString(m.SrcAddr), DstIP: ipString(m.DstAddr),
		SrcPort: uint16(m.SrcPort), DstPort: uint16(m.DstPort), InIf: m.InIf, OutIf: m.OutIf,
		Bytes: m.Bytes, Packets: m.Packets, TCPFlags: uint8(m.TcpFlags), VLAN: uint16(m.VlanId),
		SrcMAC: macString(m.SrcMac), DstMAC: macString(m.DstMac),
	}
	if m.TimeFlowStartNs > 0 {
		r.Start = time.Unix(0, int64(m.TimeFlowStartNs)).UTC()
	}
	if m.TimeFlowEndNs > 0 {
		r.End = time.Unix(0, int64(m.TimeFlowEndNs)).UTC()
	}
	if r.At.Unix() <= 0 {
		r.At = time.Now().UTC()
	}
	return r
}

func ipString(b []byte) string {
	if a, ok := netip.AddrFromSlice(b); ok && (len(b) == 4 || len(b) == 16) {
		return a.Unmap().String()
	}
	return ""
}

func macString(v uint64) string {
	if v == 0 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", byte(v>>40), byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func (e *evidence) listenFlows(ctx context.Context, port int, kind string) {
	cfg := &protoproducer.ProducerConfig{}
	mapped, err := cfg.Compile()
	if err != nil {
		e.log.Error("flow decoder", "err", err)
		return
	}
	prod, err := protoproducer.CreateProtoProducer(mapped, protoproducer.CreateSamplingSystem)
	if err != nil {
		e.log.Error("flow decoder", "err", err)
		return
	}
	var pipe utils.FlowPipe
	if kind == "sflow" {
		pipe = utils.NewSFlowPipe(&utils.PipeConfig{Format: flowSink{e}, Producer: prod})
	} else {
		pipe = utils.NewNetFlowPipe(&utils.PipeConfig{Format: flowSink{e}, Producer: prod})
	}
	pc, err := net.ListenPacket("udp", ":"+strconv.Itoa(port))
	if err != nil {
		e.log.Error("flow listen failed", "kind", kind, "port", port, "err", err)
		return
	}
	if uc, ok := pc.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(evidenceUDPBuffer)
	}
	e.addListener(fmt.Sprintf("%s/udp %d", kind, port))
	go func() { <-ctx.Done(); pc.Close(); pipe.Close() }()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			ap, _ := netip.ParseAddrPort(from.String())
			if !e.accept(ap.Addr()) {
				e.refused.Add(1)
				continue
			}
			if e.full() {
				e.dropped.Add(1)
				continue
			}
			payload := make([]byte, n)
			copy(payload, buf[:n])
			msg := &utils.Message{Src: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), Payload: payload, Received: time.Now().UTC()}
			if err := pipe.DecodeFlow(msg); err != nil {
				e.flowErrs.Add(1)
			}
		}
	}()
}

// fdbLoop snapshots the MAC and ARP tables of every polled SNMP device.
func (e *evidence) fdbLoop(ctx context.Context, every time.Duration) {
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		e.mu.Lock()
		devices := append([]proto.NetworkDevice(nil), e.devices...)
		e.mu.Unlock()
		for _, d := range devices {
			if d.Credential.Version == "proxmox" || ctx.Err() != nil {
				continue
			}
			e.snapshot(ctx, d)
		}
		t.Reset(every)
	}
}

func (e *evidence) snapshot(ctx context.Context, d proto.NetworkDevice) {
	cred := snmp.Credential{
		Version: d.Credential.Version, Community: d.Credential.Community, Username: d.Credential.Username,
		AuthProtocol: d.Credential.AuthProtocol, AuthPassword: d.Credential.AuthPassword,
		PrivProtocol: d.Credential.PrivProtocol, PrivPassword: d.Credential.PrivPassword, Context: d.Credential.Context,
	}
	sess, err := snmp.Dial(d.Address, cred, snmp.Options{})
	if err != nil {
		return
	}
	defer sess.Close()
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	rows, err := collect.FDB(cctx, sess)
	if err != nil {
		e.log.Debug("mac/arp table read failed", "device", d.ID, "err", err)
		return
	}
	at := time.Now().UTC()
	out := make([]proto.FDBEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, proto.FDBEntry{At: at, DeviceID: d.ID, Port: r.Port, IfIndex: r.IfIndex, VLAN: r.VLAN, MAC: r.MAC, IP: r.IP, Source: r.Source})
	}
	if len(out) > 0 {
		e.in <- out
	}
}

func (e *evidence) stats() proto.EvidenceStats {
	e.mu.Lock()
	l := append([]string(nil), e.listening...)
	e.mu.Unlock()
	return proto.EvidenceStats{
		Listening: l, Dropped: e.dropped.Swap(0), Refused: e.refused.Swap(0), FlowErrs: e.flowErrs.Swap(0),
		SpoolMB: float64(e.spoolBytes.Load()) / (1 << 20),
	}
}

func newBatchID() string {
	var b [12]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (e *evidence) batcher(ctx context.Context) {
	tick := time.NewTicker(evidenceFlushEvery)
	statsTick := time.NewTicker(time.Minute)
	defer tick.Stop()
	defer statsTick.Stop()
	b := proto.EvidenceBatch{}
	n := 0
	statsDue := false
	flush := func() {
		if n == 0 && !statsDue {
			return
		}
		b.ID, b.Stats = newBatchID(), e.stats()
		if err := e.write(b); err != nil {
			e.log.Error("evidence spool write failed", "err", err)
		}
		b, n, statsDue = proto.EvidenceBatch{}, 0, false
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case v := <-e.in:
			switch r := v.(type) {
			case proto.LogRecord:
				b.Logs = append(b.Logs, r)
				n++
			case proto.FlowRecord:
				b.Flows = append(b.Flows, r)
				n++
			case []proto.FDBEntry:
				b.FDB = append(b.FDB, r...)
				n += len(r)
			}
			if n >= evidenceBatchItems {
				flush()
			}
		case <-tick.C:
			flush()
		case <-statsTick.C:
			e.mu.Lock()
			statsDue = e.cfgKey != ""
			e.mu.Unlock()
		}
	}
}

func (e *evidence) write(b proto.EvidenceBatch) error {
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	name := filepath.Join(e.dir, fmt.Sprintf("%020d-%s.json", time.Now().UnixNano(), b.ID))
	if err := writeAtomic(name, data); err != nil {
		return err
	}
	e.spoolBytes.Add(int64(len(data)))
	return nil
}

// replay delivers spooled batches oldest first. A refused batch (4xx other
// than 401/403/404/413/429) is kept aside under .rejected for a person to
// look at, never deleted; everything else is retried with backoff.
func (e *evidence) replay(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		names, _ := filepath.Glob(filepath.Join(e.dir, "*.json"))
		sort.Strings(names)
		if len(names) == 0 {
			sleepCtx(ctx, time.Second)
			continue
		}
		name := names[0]
		data, err := os.ReadFile(name)
		var b proto.EvidenceBatch
		if err != nil || json.Unmarshal(data, &b) != nil {
			os.Rename(name, name+".rejected")
			e.spoolBytes.Add(-int64(len(data)))
			continue
		}
		dctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		err = e.deliver(dctx, b)
		cancel()
		var se *statusError
		switch {
		case err == nil:
			os.Remove(name)
			e.spoolBytes.Add(-int64(len(data)))
			backoff = time.Second
		case errors.As(err, &se) && se.Code >= 400 && se.Code < 500 && se.Code != 401 && se.Code != 403 &&
			se.Code != 404 && se.Code != 408 && se.Code != 413 && se.Code != 429:
			e.log.Error("ingest refused an evidence batch; kept aside", "file", filepath.Base(name), "err", err)
			os.Rename(name, name+".rejected")
			e.spoolBytes.Add(-int64(len(data)))
		default:
			e.log.Warn("evidence delivery failed; will retry", "err", err, "waiting", len(names))
			sleepCtx(ctx, backoff)
			backoff = min(backoff*2, time.Minute)
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
