// Package snmp is Beacon's SNMP abstraction. The rest of the code base talks
// to the Session interface only, never to gosnmp directly, so the underlying
// library can be patched or replaced without touching collectors or profiles.
package snmp

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Kind is the ASN.1/SMI type of a varbind value.
type Kind int

const (
	KindNull Kind = iota
	KindInteger
	KindOctetString
	KindOID
	KindIPAddress
	KindCounter32
	KindGauge32
	KindTimeTicks
	KindCounter64
	KindOpaque
)

func (k Kind) String() string {
	switch k {
	case KindInteger:
		return "integer"
	case KindOctetString:
		return "string"
	case KindOID:
		return "oid"
	case KindIPAddress:
		return "ipaddress"
	case KindCounter32:
		return "counter32"
	case KindGauge32:
		return "gauge32"
	case KindTimeTicks:
		return "timeticks"
	case KindCounter64:
		return "counter64"
	case KindOpaque:
		return "opaque"
	}
	return "null"
}

// IsCounter reports whether values of this kind are monotonically increasing counters.
func (k Kind) IsCounter() bool { return k == KindCounter32 || k == KindCounter64 }

// IsNumeric reports whether the value can be represented as a number.
func (k Kind) IsNumeric() bool {
	switch k {
	case KindInteger, KindCounter32, KindGauge32, KindTimeTicks, KindCounter64:
		return true
	}
	return false
}

// PDU is one decoded varbind. OIDs never carry a leading dot.
type PDU struct {
	OID   string
	Kind  Kind
	Int   int64  // Integer
	Uint  uint64 // Counter32, Gauge32, TimeTicks, Counter64
	Bytes []byte // OctetString, Opaque
	Str   string // OID value, IpAddress
}

// Float returns the numeric value of the PDU. ok is false for non-numeric
// kinds unless the octet string parses as a number (some vendors, e.g.
// FortiGate sensors, report numbers as strings).
func (p PDU) Float() (float64, bool) {
	switch p.Kind {
	case KindInteger:
		return float64(p.Int), true
	case KindCounter32, KindGauge32, KindTimeTicks, KindCounter64:
		return float64(p.Uint), true
	case KindOctetString:
		f, err := strconv.ParseFloat(strings.TrimSpace(string(p.Bytes)), 64)
		return f, err == nil
	}
	return 0, false
}

// String renders the value for labels and inventory. Octet strings that are
// not printable are rendered as colon-separated hex (MAC addresses, serials).
func (p PDU) String() string {
	switch p.Kind {
	case KindInteger:
		return strconv.FormatInt(p.Int, 10)
	case KindCounter32, KindGauge32, KindTimeTicks, KindCounter64:
		return strconv.FormatUint(p.Uint, 10)
	case KindOctetString, KindOpaque:
		if printable(p.Bytes) {
			return strings.TrimRight(string(p.Bytes), "\x00")
		}
		return hexString(p.Bytes)
	case KindOID, KindIPAddress:
		return p.Str
	}
	return ""
}

func printable(b []byte) bool {
	b = []byte(strings.TrimRight(string(b), "\x00"))
	for _, c := range b {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' || c > 0x7e {
			return false
		}
	}
	return true
}

func hexString(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("%02x", c)
	}
	return strings.Join(parts, ":")
}

// Session is a connection to one SNMP agent.
type Session interface {
	// Get fetches scalar OIDs. Missing objects (noSuchObject/noSuchInstance)
	// are omitted from the result rather than returned as errors.
	Get(ctx context.Context, oids []string) ([]PDU, error)
	// Walk visits every varbind under root in lexicographic order.
	Walk(ctx context.Context, root string, fn func(PDU) error) error
	Close() error
}

// ErrTimeout is returned when the agent does not answer.
var ErrTimeout = errors.New("snmp: request timeout")

// NormalizeOID strips a leading dot and surrounding space.
func NormalizeOID(o string) string { return strings.TrimPrefix(strings.TrimSpace(o), ".") }

// HasPrefix reports whether oid lies under root (component-wise).
func HasPrefix(oid, root string) bool {
	oid, root = NormalizeOID(oid), NormalizeOID(root)
	return oid == root || strings.HasPrefix(oid, root+".")
}

// Suffix returns the index part of oid below root ("" if not under root).
func Suffix(oid, root string) string {
	oid, root = NormalizeOID(oid), NormalizeOID(root)
	if !strings.HasPrefix(oid, root+".") {
		return ""
	}
	return oid[len(root)+1:]
}

// CompareOID orders two dotted OIDs numerically, component by component.
func CompareOID(a, b string) int {
	as, bs := strings.Split(NormalizeOID(a), "."), strings.Split(NormalizeOID(b), ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, _ := strconv.ParseUint(as[i], 10, 64)
		y, _ := strconv.ParseUint(bs[i], 10, 64)
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return len(as) - len(bs)
}
