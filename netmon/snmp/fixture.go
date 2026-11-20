package snmp

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// FixtureSession replays a recorded walk (net-snmp `snmpwalk -On -Oe -OU -Ot`
// output) as if it were a live agent. It is used by profile tests and by
// `beacon-walk --fixture`.
type FixtureSession struct {
	pdus []PDU // sorted by OID
	// FailRoots simulates agents that return genErr for these subtrees.
	FailRoots []string
	// NoBulk simulates agents (TP-Link) that return nothing to GetBulk.
	NoBulk bool
}

// LoadFixture parses a walk file.
func LoadFixture(path string) (*FixtureSession, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseWalk(f)
}

// ParseWalk parses walk output. Multi-line string values are joined.
func ParseWalk(r io.Reader) (*FixtureSession, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	var out []PDU
	var cur *PDU
	var pendingStr []string
	flush := func() {
		if cur != nil {
			if cur.Kind == KindOctetString && pendingStr != nil {
				cur.Bytes = []byte(strings.Join(pendingStr, "\n"))
			}
			out = append(out, *cur)
		}
		cur, pendingStr = nil, nil
	}
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, ".") || !strings.Contains(line, " = ") {
			// continuation of a multi-line string value
			if cur != nil && cur.Kind == KindOctetString && pendingStr != nil {
				pendingStr = append(pendingStr, strings.TrimSuffix(line, `"`))
			}
			continue
		}
		flush()
		oid, val, _ := strings.Cut(line, " = ")
		p, multi, err := parseValue(NormalizeOID(oid), val)
		if err != nil {
			continue // skip lines we cannot decode (e.g. "No more variables")
		}
		cur = &p
		if multi {
			pendingStr = []string{strings.TrimPrefix(val[len("STRING: "):], `"`)}
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool { return CompareOID(out[i].OID, out[j].OID) < 0 })
	// de-duplicate (walks of overlapping subtrees)
	dedup := out[:0]
	for i, p := range out {
		if i > 0 && p.OID == out[i-1].OID {
			continue
		}
		dedup = append(dedup, p)
	}
	return &FixtureSession{pdus: dedup}, nil
}

func parseValue(oid, val string) (PDU, bool, error) {
	p := PDU{OID: oid}
	typ, rest, hasType := strings.Cut(val, ": ")
	if !hasType {
		// -Ot prints raw TimeTicks without a type; empty strings print as "".
		v := strings.TrimSpace(val)
		if v == `""` || v == "" {
			p.Kind = KindOctetString
			p.Bytes = []byte{}
			return p, false, nil
		}
		if strings.HasSuffix(v, ":") { // "STRING:" with empty value
			p.Kind = KindOctetString
			p.Bytes = []byte{}
			return p, false, nil
		}
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return p, false, err
		}
		p.Kind, p.Uint = KindTimeTicks, n
		return p, false, nil
	}
	switch typ {
	case "INTEGER":
		n, err := strconv.ParseInt(strings.Fields(rest + " ")[0], 10, 64)
		if err != nil {
			return p, false, err
		}
		p.Kind, p.Int = KindInteger, n
	case "Counter32", "Gauge32", "Counter64", "Timeticks", "Unsigned32":
		n, err := strconv.ParseUint(strings.Fields(rest + " ")[0], 10, 64)
		if err != nil {
			return p, false, err
		}
		p.Uint = n
		p.Kind = map[string]Kind{"Counter32": KindCounter32, "Gauge32": KindGauge32, "Unsigned32": KindGauge32, "Counter64": KindCounter64, "Timeticks": KindTimeTicks}[typ]
	case "STRING":
		p.Kind = KindOctetString
		s := rest
		if strings.HasPrefix(s, `"`) {
			if len(s) >= 2 && strings.HasSuffix(s, `"`) {
				s = s[1 : len(s)-1]
			} else {
				return p, true, nil // multi-line quoted string
			}
		}
		p.Bytes = []byte(s)
	case "Hex-STRING":
		b, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(rest), " ", ""))
		if err != nil {
			return p, false, err
		}
		p.Kind, p.Bytes = KindOctetString, b
	case "OID":
		p.Kind, p.Str = KindOID, NormalizeOID(rest)
	case "IpAddress":
		p.Kind, p.Str = KindIPAddress, strings.TrimSpace(rest)
	case "Opaque":
		p.Kind, p.Bytes = KindOpaque, []byte(rest)
	default:
		return p, false, fmt.Errorf("unknown type %q", typ)
	}
	if strings.HasSuffix(val, ":") { // "STRING:" with nothing after it
		p.Kind, p.Bytes = KindOctetString, []byte{}
	}
	return p, false, nil
}

// Len returns the number of recorded varbinds.
func (f *FixtureSession) Len() int { return len(f.pdus) }

func (f *FixtureSession) find(oid string) (PDU, bool) {
	i := sort.Search(len(f.pdus), func(i int) bool { return CompareOID(f.pdus[i].OID, oid) >= 0 })
	if i < len(f.pdus) && f.pdus[i].OID == oid {
		return f.pdus[i], true
	}
	return PDU{}, false
}

// Get implements Session.
func (f *FixtureSession) Get(_ context.Context, oids []string) ([]PDU, error) {
	var out []PDU
	for _, o := range oids {
		if p, ok := f.find(NormalizeOID(o)); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

// Walk implements Session.
func (f *FixtureSession) Walk(ctx context.Context, root string, fn func(PDU) error) error {
	root = NormalizeOID(root)
	for _, fr := range f.FailRoots {
		if HasPrefix(root, fr) || HasPrefix(fr, root) {
			return &AgentError{Status: "genErr", OID: root}
		}
	}
	i := sort.Search(len(f.pdus), func(i int) bool { return CompareOID(f.pdus[i].OID, root) > 0 })
	for ; i < len(f.pdus) && HasPrefix(f.pdus[i].OID, root); i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(f.pdus[i]); err != nil {
			return err
		}
	}
	return nil
}

// Close implements Session.
func (f *FixtureSession) Close() error { return nil }

// AgentError is an error-status returned by the agent (genErr, tooBig, ...).
type AgentError struct {
	Status string
	OID    string
}

func (e *AgentError) Error() string { return "snmp: agent returned " + e.Status + " at " + e.OID }
