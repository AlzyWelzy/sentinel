package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AlzyWelzy/sentinel/proto"
)

func freePort(t *testing.T, network string) int {
	t.Helper()
	if network == "udp" {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		return pc.LocalAddr().(*net.UDPAddr).Port
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// netflowV5 builds one NetFlow v5 packet with one record.
func netflowV5(src, dst net.IP, bytes uint32) []byte {
	b := make([]byte, 24+48)
	binary.BigEndian.PutUint16(b[0:], 5)
	binary.BigEndian.PutUint16(b[2:], 1)
	binary.BigEndian.PutUint32(b[8:], uint32(time.Now().Unix()))
	r := b[24:]
	copy(r[0:4], src.To4())
	copy(r[4:8], dst.To4())
	binary.BigEndian.PutUint32(r[16:], 3)     // packets
	binary.BigEndian.PutUint32(r[20:], bytes) // octets
	binary.BigEndian.PutUint16(r[32:], 51000)
	binary.BigEndian.PutUint16(r[34:], 443)
	r[38] = 6
	return b
}

func TestEvidenceReceivers(t *testing.T) {
	t.Setenv("SENTINEL_EVIDENCE_STANDARD_PORTS", "0")
	var mu sync.Mutex
	var got []proto.EvidenceBatch
	fail := true
	deliver := func(_ context.Context, b proto.EvidenceBatch) error {
		mu.Lock()
		defer mu.Unlock()
		if fail { // the first delivery fails: the batch must stay spooled
			fail = false
			return errors.New("ingest down")
		}
		got = append(got, b)
		return nil
	}
	e, err := newEvidence(t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), deliver)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.start(ctx)
	udp, tcp, nf := freePort(t, "udp"), freePort(t, "tcp"), freePort(t, "udp")
	e.set(ctx, &proto.EvidenceConfig{SyslogUDP: udp, SyslogTCP: tcp, NetFlow: nf}, []proto.NetworkDevice{{ID: "fw", Address: "127.0.0.1"}})
	time.Sleep(200 * time.Millisecond)

	c, _ := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", udp))
	c.Write([]byte("<134>date=2026-11-21 devname=\"fw1\" type=\"traffic\" srcip=10.0.0.5 dstip=8.8.8.8\n<134>second line"))
	c.Close()
	tc, _ := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tcp))
	msg := "<134>octet framed message"
	fmt.Fprintf(tc, "%d %s", len(msg), msg)
	tc.Write([]byte("<134>lf framed\n"))
	tc.Close()
	fc, _ := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", nf))
	fc.Write(netflowV5(net.ParseIP("10.0.0.5"), net.ParseIP("1.1.1.1"), 1500))
	fc.Close()

	var logs, flows int
	var flow proto.FlowRecord
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && (logs < 4 || flows < 1) {
		time.Sleep(200 * time.Millisecond)
		mu.Lock()
		logs, flows = 0, 0
		for _, b := range got {
			logs += len(b.Logs)
			flows += len(b.Flows)
			if len(b.Flows) > 0 {
				flow = b.Flows[0]
			}
		}
		mu.Unlock()
	}
	if logs != 4 || flows != 1 {
		t.Fatalf("logs %d flows %d", logs, flows)
	}
	if flow.SrcIP != "10.0.0.5" || flow.DstIP != "1.1.1.1" || flow.Bytes != 1500 || flow.DstPort != 443 || flow.Type != "netflow5" {
		t.Fatalf("flow: %+v", flow)
	}

	// A sender that isn't a polled device or an allowed range is refused.
	e.set(ctx, &proto.EvidenceConfig{SyslogUDP: udp, SyslogTCP: tcp, NetFlow: nf}, nil)
	c, _ = net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", udp))
	c.Write([]byte("<134>from a stranger"))
	c.Close()
	time.Sleep(300 * time.Millisecond)
	if e.refused.Load() == 0 {
		t.Fatal("a stranger's syslog was accepted")
	}
}

func TestReadFrame(t *testing.T) {
	for in, want := range map[string]string{"11 hello world": "hello world", "<1>x\n": "<1>x\n", "9999999999 x\n": "9999999999 x\n"} {
		r := bufioReader(in)
		if got, _ := readFrame(r); got != want {
			t.Errorf("%q: got %q", in, got)
		}
	}
}

func bufioReader(s string) *bufio.Reader { return bufio.NewReader(strings.NewReader(s)) }
