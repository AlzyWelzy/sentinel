// Package profile loads vendor profiles: YAML files that declare which SNMP
// objects to collect for a device family and how to turn them into metrics.
// Adding a vendor is a new YAML file, not new Go code.
package profile

import (
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/AlzyWelzy/pulsegrid-beyond/netmon/snmp"
)

// Interval classes; the device's poll settings map them to durations.
const (
	Fast   = "fast"   // interfaces (default 30s)
	Normal = "normal" // health (default 60s)
	Slow   = "slow"   // inventory-like tables (default 5m)
)

// Profile describes one device family.
type Profile struct {
	Name        string   `yaml:"name"`
	Vendor      string   `yaml:"vendor"`
	Description string   `yaml:"description"`
	Extends     []string `yaml:"extends"`
	Match       Match    `yaml:"match"`
	SNMP        SNMP     `yaml:"snmp"`
	// Interfaces and LLDP are collected by built-in code (they need special
	// handling: HC/32-bit fallback, stable naming, neighbour decoding).
	Interfaces *bool               `yaml:"interfaces"`
	LLDP       *bool               `yaml:"lldp"`
	Scalars    []Scalar            `yaml:"scalars"`
	Tables     []Table             `yaml:"tables"`
	Inventory  map[string]InvField `yaml:"inventory"`
	Alerts     []AlertTemplate     `yaml:"alerts"`

	sysDescrRe *regexp.Regexp
	abstract   bool
}

// Match selects devices by sysObjectID prefix and optional sysDescr regex.
type Match struct {
	SysObjectID []string `yaml:"sys_object_id"`
	SysDescr    string   `yaml:"sys_descr"`
}

// SNMP holds transport quirks for the device family.
type SNMP struct {
	MaxRepetitions uint32   `yaml:"max_repetitions"`
	UseGetNext     bool     `yaml:"use_getnext"`
	SkipRoots      []string `yaml:"skip_roots"` // never walk these (agents return genErr / are too slow)
}

// Scalar is a single-instance object.
type Scalar struct {
	Name     string            `yaml:"name"`
	OID      string            `yaml:"oid"`
	Type     string            `yaml:"type"` // gauge (default) | counter
	Help     string            `yaml:"help"`
	Scale    float64           `yaml:"scale"`
	Labels   map[string]string `yaml:"labels"`
	States   map[int]string    `yaml:"states"`
	Interval string            `yaml:"interval"`
}

// Table is a conceptual row set sharing an index.
type Table struct {
	Name      string            `yaml:"name"`
	Index     string            `yaml:"index"` // label holding the row index (default "index")
	Labels    map[string]Column `yaml:"labels"`
	Metrics   []Column          `yaml:"metrics"`
	Exclude   []Filter          `yaml:"exclude"`
	Include   []Filter          `yaml:"include"`
	Transform string            `yaml:"transform"` // "entity_sensor"
	Interval  string            `yaml:"interval"`
}

// Column is one table column.
type Column struct {
	Name       string         `yaml:"name"`
	OID        string         `yaml:"oid"`
	Type       string         `yaml:"type"`
	Help       string         `yaml:"help"`
	Scale      float64        `yaml:"scale"`
	MultiplyBy string         `yaml:"multiply_by"` // OID of another column in the same row
	States     map[int]string `yaml:"states"`
	Map        map[int]string `yaml:"map"` // label value mapping for enum label columns
	Ignore     []float64      `yaml:"ignore"`
}

// Filter matches a label value by regex.
type Filter struct {
	Label string `yaml:"label"`
	Regex string `yaml:"regex"`
	re    *regexp.Regexp
}

// InvField is an inventory attribute (stored in the device record, not as a metric).
type InvField struct {
	OID   string            `yaml:"oid"`
	Regex string            `yaml:"regex"` // first capture group is used
	Map   map[string]string `yaml:"map"`
	re    *regexp.Regexp
}

// AlertTemplate is a default alert rule installed for devices using the profile.
type AlertTemplate struct {
	Name     string `yaml:"name"`
	Expr     string `yaml:"expr"`
	For      string `yaml:"for"`
	Severity string `yaml:"severity"`
	Summary  string `yaml:"summary"`
}

// Bool returns the value of an optional flag with a default.
func Bool(b *bool, def bool) bool {
	if b == nil {
		return def
	}
	return *b
}

// Registry holds resolved profiles.
type Registry struct {
	byName map[string]*Profile
}

// Load parses every *.yaml file in fsys and resolves `extends`.
func Load(fsys fs.FS) (*Registry, error) {
	raw := map[string]*Profile{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || (path.Ext(p) != ".yaml" && path.Ext(p) != ".yml") {
			return err
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		var pr Profile
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		dec.KnownFields(true)
		if err := dec.Decode(&pr); err != nil {
			return fmt.Errorf("profile %s: %w", p, err)
		}
		if pr.Name == "" {
			return fmt.Errorf("profile %s: missing name", p)
		}
		if _, dup := raw[pr.Name]; dup {
			return fmt.Errorf("profile %s: duplicate name %q", p, pr.Name)
		}
		pr.abstract = strings.HasPrefix(pr.Name, "_")
		raw[pr.Name] = &pr
		return nil
	})
	if err != nil {
		return nil, err
	}
	reg := &Registry{byName: map[string]*Profile{}}
	for name := range raw {
		p, err := resolve(name, raw, nil)
		if err != nil {
			return nil, err
		}
		if err := p.compile(); err != nil {
			return nil, fmt.Errorf("profile %s: %w", name, err)
		}
		reg.byName[name] = p
	}
	if _, ok := reg.byName["generic"]; !ok {
		return nil, fmt.Errorf("profiles: a profile named \"generic\" is required as fallback")
	}
	return reg, nil
}

func resolve(name string, raw map[string]*Profile, stack []string) (*Profile, error) {
	for _, s := range stack {
		if s == name {
			return nil, fmt.Errorf("profiles: extends cycle %v -> %s", stack, name)
		}
	}
	p, ok := raw[name]
	if !ok {
		return nil, fmt.Errorf("profiles: unknown profile %q (extended by %v)", name, stack)
	}
	out := Profile{Inventory: map[string]InvField{}}
	for _, parent := range p.Extends {
		pp, err := resolve(parent, raw, append(stack, name))
		if err != nil {
			return nil, err
		}
		merge(&out, pp)
	}
	merge(&out, p)
	out.Name, out.Vendor, out.Description, out.Match, out.abstract = p.Name, p.Vendor, p.Description, p.Match, p.abstract
	out.Extends = p.Extends
	return &out, nil
}

func merge(dst, src *Profile) {
	if src.SNMP.MaxRepetitions != 0 {
		dst.SNMP.MaxRepetitions = src.SNMP.MaxRepetitions
	}
	dst.SNMP.UseGetNext = dst.SNMP.UseGetNext || src.SNMP.UseGetNext
	dst.SNMP.SkipRoots = append(dst.SNMP.SkipRoots, src.SNMP.SkipRoots...)
	if src.Interfaces != nil {
		dst.Interfaces = src.Interfaces
	}
	if src.LLDP != nil {
		dst.LLDP = src.LLDP
	}
	dst.Scalars = append(dst.Scalars, src.Scalars...)
	dst.Tables = append(dst.Tables, src.Tables...)
	for k, v := range src.Inventory {
		dst.Inventory[k] = v
	}
	dst.Alerts = append(dst.Alerts, src.Alerts...)
}

var metricName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func (p *Profile) compile() error {
	if p.Match.SysDescr != "" {
		re, err := regexp.Compile(p.Match.SysDescr)
		if err != nil {
			return err
		}
		p.sysDescrRe = re
	}
	for i := range p.Scalars {
		s := &p.Scalars[i]
		if !metricName.MatchString(s.Name) || s.OID == "" {
			return fmt.Errorf("scalar %q: invalid name or missing oid", s.Name)
		}
		s.OID = snmp.NormalizeOID(s.OID)
	}
	for i := range p.Tables {
		t := &p.Tables[i]
		if !metricName.MatchString(t.Name) {
			return fmt.Errorf("table %q: invalid name", t.Name)
		}
		if t.Index == "" {
			t.Index = "index"
		}
		for k, c := range t.Labels {
			c.OID = snmp.NormalizeOID(c.OID)
			t.Labels[k] = c
		}
		for j := range t.Metrics {
			c := &t.Metrics[j]
			if !metricName.MatchString(c.Name) || c.OID == "" {
				return fmt.Errorf("table %s metric %q: invalid name or missing oid", t.Name, c.Name)
			}
			c.OID = snmp.NormalizeOID(c.OID)
			c.MultiplyBy = snmp.NormalizeOID(c.MultiplyBy)
		}
		for _, fl := range []*[]Filter{&t.Exclude, &t.Include} {
			for j := range *fl {
				re, err := regexp.Compile((*fl)[j].Regex)
				if err != nil {
					return err
				}
				(*fl)[j].re = re
			}
		}
	}
	for k, f := range p.Inventory {
		f.OID = snmp.NormalizeOID(f.OID)
		if f.Regex != "" {
			re, err := regexp.Compile(f.Regex)
			if err != nil {
				return fmt.Errorf("inventory %s: %w", k, err)
			}
			f.re = re
		}
		p.Inventory[k] = f
	}
	for i := range p.SNMP.SkipRoots {
		p.SNMP.SkipRoots[i] = snmp.NormalizeOID(p.SNMP.SkipRoots[i])
	}
	return nil
}

// Get returns a profile by name.
func (r *Registry) Get(name string) (*Profile, bool) {
	p, ok := r.byName[name]
	return p, ok && !p.abstract
}

// Names lists concrete profile names.
func (r *Registry) Names() []string {
	var out []string
	for n, p := range r.byName {
		if !p.abstract {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// Detect picks the most specific profile for a device: the longest matching
// sysObjectID prefix wins; a sysDescr regex, if present, must also match.
func (r *Registry) Detect(sysObjectID, sysDescr string) *Profile {
	sysObjectID = snmp.NormalizeOID(sysObjectID)
	var best *Profile
	bestLen := -1
	for _, p := range r.byName {
		if p.abstract {
			continue
		}
		descrOK := p.sysDescrRe != nil && p.sysDescrRe.MatchString(sysDescr)
		if p.sysDescrRe != nil && !descrOK {
			continue
		}
		matched := false
		for _, pre := range p.Match.SysObjectID {
			pre = snmp.NormalizeOID(strings.TrimSuffix(pre, ".*"))
			if snmp.HasPrefix(sysObjectID, pre) {
				matched = true
				if len(pre) > bestLen {
					best, bestLen = p, len(pre)
				}
			}
		}
		// A sysDescr match alone is enough for agents with broken
		// sysObjectIDs (TP-Link JetStream reports iso.0.3.0.6...).
		if !matched && descrOK && bestLen < 0 {
			best, bestLen = p, 0
		}
	}
	if best == nil {
		best = r.byName["generic"]
	}
	return best
}

// Skipped reports whether root is configured to be skipped.
func (p *Profile) Skipped(oid string) bool {
	for _, s := range p.SNMP.SkipRoots {
		if snmp.HasPrefix(oid, s) {
			return true
		}
	}
	return false
}

// Matches applies include/exclude filters to a row's labels.
func (t *Table) Matches(labels map[string]string) bool {
	for _, f := range t.Exclude {
		if f.re.MatchString(labels[f.Label]) {
			return false
		}
	}
	if len(t.Include) == 0 {
		return true
	}
	for _, f := range t.Include {
		if f.re.MatchString(labels[f.Label]) {
			return true
		}
	}
	return false
}

// Extract applies the inventory field regex/map to a raw value.
func (f InvField) Extract(v string) string {
	if f.re != nil {
		m := f.re.FindStringSubmatch(v)
		if len(m) < 2 {
			return ""
		}
		v = m[1]
	}
	if mv, ok := f.Map[v]; ok {
		return mv
	}
	return strings.TrimSpace(v)
}
