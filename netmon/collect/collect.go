// Package collect runs a profile against an SNMP session and produces
// metric samples, inventory, interfaces and LLDP neighbours.
package collect

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/AlzyWelzy/pulsegrid-beyond/netmon/profile"
	"github.com/AlzyWelzy/pulsegrid-beyond/netmon/snmp"
)

// Standard OIDs.
const (
	oidSysDescr    = "1.3.6.1.2.1.1.1.0"
	oidSysObjectID = "1.3.6.1.2.1.1.2.0"
	oidSysUpTime   = "1.3.6.1.2.1.1.3.0"
	oidSysContact  = "1.3.6.1.2.1.1.4.0"
	oidSysName     = "1.3.6.1.2.1.1.5.0"
	oidSysLocation = "1.3.6.1.2.1.1.6.0"
)

// Sample is one metric value. Name excludes the "beacon_" prefix.
type Sample struct {
	Name    string            `json:"n"`
	Labels  map[string]string `json:"l,omitempty"`
	Value   float64           `json:"v"`
	Counter bool              `json:"c,omitempty"`
}

// System is the MIB-II system group.
type System struct {
	Descr     string  `json:"descr"`
	ObjectID  string  `json:"object_id"`
	Name      string  `json:"name"`
	Contact   string  `json:"contact,omitempty"`
	Location  string  `json:"location,omitempty"`
	UptimeSec float64 `json:"uptime_sec"`
}

// Interface is the inventory view of one interface.
type Interface struct {
	Index      int    `json:"index"`
	Name       string `json:"name"`
	Descr      string `json:"descr,omitempty"`
	Alias      string `json:"alias,omitempty"`
	Type       int    `json:"type"`
	SpeedBps   uint64 `json:"speed_bps"`
	MTU        int    `json:"mtu,omitempty"`
	MAC        string `json:"mac,omitempty"`
	AdminUp    bool   `json:"admin_up"`
	OperStatus int    `json:"oper_status"`
	HighCap    bool   `json:"high_capacity"`
}

// Neighbor is one LLDP neighbour as seen from the local device.
type Neighbor struct {
	LocalPort      string `json:"local_port"`
	RemoteSysName  string `json:"remote_sys_name"`
	RemotePortID   string `json:"remote_port_id"`
	RemotePortDesc string `json:"remote_port_desc,omitempty"`
	RemoteChassis  string `json:"remote_chassis_id,omitempty"`
	RemoteMgmtAddr string `json:"remote_mgmt_addr,omitempty"`
}

// Result of one poll.
type Result struct {
	Profile    string            `json:"profile"`
	System     System            `json:"system"`
	Samples    []Sample          `json:"samples"`
	Inventory  map[string]string `json:"inventory,omitempty"`
	Interfaces []Interface       `json:"interfaces,omitempty"`
	Neighbors  []Neighbor        `json:"neighbors,omitempty"`
	Errors     []string          `json:"errors,omitempty"`
	Duration   time.Duration     `json:"duration_ns"`
	Requests   int64             `json:"requests"`
}

// Options select what to collect in this run.
type Options struct {
	// Classes to include; nil means all.
	Classes   map[string]bool
	Inventory bool // collect inventory, interface metadata and LLDP
}

func (o Options) want(class string) bool {
	if class == "" {
		class = profile.Normal
	}
	return o.Classes == nil || o.Classes[class]
}

// Identify reads the system group. It is the only call made before a profile is known.
func Identify(ctx context.Context, s snmp.Session) (System, error) {
	pdus, err := s.Get(ctx, []string{oidSysDescr, oidSysObjectID, oidSysUpTime, oidSysName, oidSysContact, oidSysLocation})
	if err != nil {
		return System{}, err
	}
	var sys System
	for _, p := range pdus {
		switch p.OID {
		case oidSysDescr:
			sys.Descr = p.String()
		case oidSysObjectID:
			sys.ObjectID = p.String()
		case oidSysUpTime:
			v, _ := p.Float()
			sys.UptimeSec = v / 100
		case oidSysName:
			sys.Name = p.String()
		case oidSysContact:
			sys.Contact = p.String()
		case oidSysLocation:
			sys.Location = p.String()
		}
	}
	if sys.ObjectID == "" && sys.Descr == "" && sys.Name == "" {
		return sys, errors.New("snmp: agent returned no system group")
	}
	return sys, nil
}

// Run polls the device with the given profile.
func Run(ctx context.Context, s snmp.Session, p *profile.Profile, opts Options) *Result {
	start := time.Now()
	r := &Result{Profile: p.Name}
	sys, err := Identify(ctx, s)
	if err != nil {
		r.Errors = append(r.Errors, "system: "+err.Error())
		r.Duration = time.Since(start)
		return r
	}
	r.System = sys
	r.add("device_uptime_seconds", nil, sys.UptimeSec, false)

	c := &walker{s: s, p: p, r: r, cache: map[string]map[string]snmp.PDU{}}
	if profile.Bool(p.Interfaces, true) && (opts.want(profile.Fast) || opts.Inventory) {
		c.interfaces(ctx, opts)
	}
	c.scalars(ctx, opts)
	for i := range p.Tables {
		if opts.want(p.Tables[i].Interval) {
			c.table(ctx, &p.Tables[i])
		}
	}
	if opts.Inventory {
		c.inventory(ctx)
		if profile.Bool(p.LLDP, true) {
			c.lldp(ctx)
		}
	}
	if cl, ok := s.(interface{ RequestCount() int64 }); ok {
		r.Requests = cl.RequestCount()
	}
	r.Duration = time.Since(start)
	return r
}

func (r *Result) add(name string, labels map[string]string, v float64, counter bool) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return
	}
	r.Samples = append(r.Samples, Sample{Name: name, Labels: labels, Value: v, Counter: counter})
}

type walker struct {
	s       snmp.Session
	p       *profile.Profile
	r       *Result
	cache   map[string]map[string]snmp.PDU // column OID -> index -> PDU
	ifNames map[string]string              // ifIndex -> label name
}

// column walks one column and returns index -> PDU, caching the result.
func (w *walker) column(ctx context.Context, oid string) map[string]snmp.PDU {
	if oid == "" {
		return nil
	}
	if m, ok := w.cache[oid]; ok {
		return m
	}
	m := map[string]snmp.PDU{}
	w.cache[oid] = m
	if w.p.Skipped(oid) {
		return m
	}
	err := w.s.Walk(ctx, oid, func(p snmp.PDU) error {
		if idx := snmp.Suffix(p.OID, oid); idx != "" {
			m[idx] = p
		}
		return nil
	})
	if err != nil {
		w.r.Errors = append(w.r.Errors, fmt.Sprintf("walk %s: %v", oid, err))
	}
	return m
}

func (w *walker) scalars(ctx context.Context, opts Options) {
	var oids []string
	for _, s := range w.p.Scalars {
		if opts.want(s.Interval) && !w.p.Skipped(s.OID) {
			oids = append(oids, s.OID)
		}
	}
	if len(oids) == 0 {
		return
	}
	pdus, err := w.s.Get(ctx, oids)
	if err != nil {
		w.r.Errors = append(w.r.Errors, "scalars: "+err.Error())
	}
	got := map[string]snmp.PDU{}
	for _, p := range pdus {
		got[p.OID] = p
	}
	for _, s := range w.p.Scalars {
		p, ok := got[s.OID]
		if !ok {
			continue
		}
		v, ok := p.Float()
		if !ok {
			continue
		}
		if s.Scale != 0 {
			v *= s.Scale
		}
		w.r.add(s.Name, copyMap(s.Labels), v, s.Type == "counter" || (s.Type == "" && p.Kind.IsCounter()))
	}
}

func (w *walker) table(ctx context.Context, t *profile.Table) {
	labelCols := map[string]map[string]snmp.PDU{}
	for name, col := range t.Labels {
		labelCols[name] = w.column(ctx, col.OID)
	}
	for _, m := range t.Metrics {
		vals := w.column(ctx, m.OID)
		var mult map[string]snmp.PDU
		if m.MultiplyBy != "" {
			mult = w.column(ctx, m.MultiplyBy)
		}
		for _, idx := range sortedKeys(vals) {
			pdu := vals[idx]
			v, ok := pdu.Float()
			if !ok || contains(m.Ignore, v) {
				continue
			}
			labels := map[string]string{t.Index: idx}
			for name, col := range labelCols {
				if lp, ok := col[idx]; ok {
					labels[name] = labelValue(lp, t.Labels[name])
				}
			}
			if !t.Matches(labels) {
				continue
			}
			if mult != nil {
				mp, ok := mult[idx]
				if !ok {
					continue
				}
				f, _ := mp.Float()
				v *= f
			}
			if m.Scale != 0 {
				v *= m.Scale
			}
			if t.Transform == "entity_sensor" {
				var ok bool
				if v, ok = w.entitySensor(ctx, idx, v, labels); !ok {
					continue
				}
			}
			counter := m.Type == "counter" || (m.Type == "" && pdu.Kind.IsCounter())
			w.r.add(t.Name+"_"+m.Name, labels, v, counter)
		}
	}
}

// ENTITY-SENSOR-MIB value normalisation (RFC 3433):
// value * 10^(3*(scale-9)) / 10^precision. Rows with operStatus != ok(1) are dropped.
const (
	oidEntSensorType      = "1.3.6.1.2.1.99.1.1.1.1"
	oidEntSensorScale     = "1.3.6.1.2.1.99.1.1.1.2"
	oidEntSensorPrecision = "1.3.6.1.2.1.99.1.1.1.3"
	oidEntSensorStatus    = "1.3.6.1.2.1.99.1.1.1.5"
)

var sensorTypes = map[int]string{1: "other", 2: "unknown", 3: "volts_ac", 4: "volts_dc", 5: "amperes", 6: "watts", 7: "hertz", 8: "celsius", 9: "percent_rh", 10: "rpm", 11: "cmm", 12: "truthvalue", 13: "special", 14: "dbm"}

// SensorFactor returns the multiplier for an ENTITY-SENSOR scale/precision pair.
func SensorFactor(scale, precision int) float64 {
	return math.Pow(10, float64(3*(scale-9))) / math.Pow(10, float64(precision))
}

func (w *walker) entitySensor(ctx context.Context, idx string, raw float64, labels map[string]string) (float64, bool) {
	if st, ok := w.column(ctx, oidEntSensorStatus)[idx]; ok && st.Int != 1 {
		return 0, false
	}
	scale, precision := 9, 0
	if p, ok := w.column(ctx, oidEntSensorScale)[idx]; ok {
		scale = int(p.Int)
	}
	if p, ok := w.column(ctx, oidEntSensorPrecision)[idx]; ok {
		precision = int(p.Int)
	}
	if p, ok := w.column(ctx, oidEntSensorType)[idx]; ok {
		labels["type"] = sensorTypes[int(p.Int)]
	}
	return raw * SensorFactor(scale, precision), true
}

func labelValue(p snmp.PDU, c profile.Column) string {
	if c.Map != nil {
		switch p.Kind {
		case snmp.KindInteger:
			if v, ok := c.Map[int(p.Int)]; ok {
				return v
			}
		case snmp.KindOID: // e.g. hrStorageType: map the last arc
			parts := strings.Split(p.Str, ".")
			if v, ok := c.Map[atoi(parts[len(parts)-1])]; ok {
				return v
			}
		}
	}
	return strings.TrimSpace(p.String())
}

func (w *walker) inventory(ctx context.Context) {
	if len(w.p.Inventory) == 0 {
		return
	}
	keys := make([]string, 0, len(w.p.Inventory))
	var oids []string
	for k, f := range w.p.Inventory {
		keys = append(keys, k)
		oids = append(oids, f.OID)
	}
	pdus, err := w.s.Get(ctx, oids)
	if err != nil {
		w.r.Errors = append(w.r.Errors, "inventory: "+err.Error())
	}
	byOID := map[string]snmp.PDU{}
	for _, p := range pdus {
		byOID[p.OID] = p
	}
	w.r.Inventory = map[string]string{}
	for _, k := range keys {
		f := w.p.Inventory[k]
		if p, ok := byOID[f.OID]; ok {
			if v := f.Extract(p.String()); v != "" {
				w.r.Inventory[k] = v
			}
		}
	}
}

func sortedKeys(m map[string]snmp.PDU) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return snmp.CompareOID(out[i], out[j]) < 0 })
	return out
}

func contains(xs []float64, v float64) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func copyMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }
