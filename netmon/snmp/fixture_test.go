package snmp

import (
	"context"
	"strings"
	"testing"
)

const sample = `.1.3.6.1.2.1.1.1.0 = STRING: Arista Networks EOS
.1.3.6.1.2.1.1.2.0 = OID: .1.3.6.1.4.1.30065.1.3011.7050
.1.3.6.1.2.1.1.3.0 = 3929382943
.1.3.6.1.2.1.1.4.0 = ""
.1.3.6.1.2.1.1.6.0 = STRING: "line one
line two"
.1.3.6.1.2.1.2.2.1.10.1 = Counter32: 42
.1.3.6.1.2.1.2.2.1.8.1 = INTEGER: 1
.1.3.6.1.2.1.31.1.1.1.6.1 = Counter64: 18446744073709551615
.1.3.6.1.2.1.31.1.1.1.1.1 = STRING: Ethernet1
.1.3.6.1.2.1.2.2.1.6.1 = Hex-STRING: 00 1C 73 AA BB CC
.1.3.6.1.2.1.4.20.1.1.10.0.0.1 = IpAddress: 10.0.0.1
`

func TestParseWalk(t *testing.T) {
	f, err := ParseWalk(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if f.Len() != 11 {
		t.Fatalf("want 11 pdus, got %d", f.Len())
	}
	ctx := context.Background()
	got, _ := f.Get(ctx, []string{"1.3.6.1.2.1.1.3.0", ".1.3.6.1.2.1.1.6.0", "1.3.6.1.2.1.2.2.1.6.1", "1.2.3"})
	if len(got) != 3 {
		t.Fatalf("want 3 got %d", len(got))
	}
	if got[0].Kind != KindTimeTicks || got[0].Uint != 3929382943 {
		t.Errorf("timeticks: %+v", got[0])
	}
	if got[1].String() != "line one\nline two" {
		t.Errorf("multiline: %q", got[1].String())
	}
	if got[2].String() != "00:1c:73:aa:bb:cc" {
		t.Errorf("mac: %q", got[2].String())
	}
	var n int
	_ = f.Walk(ctx, "1.3.6.1.2.1.2", func(p PDU) error { n++; return nil })
	if n != 3 {
		t.Errorf("walk ifTable want 3 got %d", n)
	}
	f.FailRoots = []string{"1.3.6.1.2.1.31"}
	if err := f.Walk(ctx, "1.3.6.1.2.1.31.1", func(PDU) error { return nil }); err == nil {
		t.Error("expected genErr")
	}
}

func TestCompareOID(t *testing.T) {
	if CompareOID("1.3.6.1.2.1.2.2.1.10.9", "1.3.6.1.2.1.2.2.1.10.10") >= 0 {
		t.Error("numeric ordering broken")
	}
	if !HasPrefix("1.3.6.1.2.1.10", "1.3.6.1.2.1.1") == true && HasPrefix("1.3.6.1.2.1.10", "1.3.6.1.2.1.1") {
		t.Error("prefix must be component-wise")
	}
	if Suffix("1.3.6.1.2.1.31.1.1.1.6.29", "1.3.6.1.2.1.31.1.1.1.6") != "29" {
		t.Error("suffix")
	}
}
