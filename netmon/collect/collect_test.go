package collect_test

import (
	"context"
	"math"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AlzyWelzy/pulsegrid-beyond/netmon/collect"
	"github.com/AlzyWelzy/pulsegrid-beyond/netmon/profile"
	"github.com/AlzyWelzy/pulsegrid-beyond/netmon/profiles"
	"github.com/AlzyWelzy/pulsegrid-beyond/netmon/snmp"
)

// These expectations come from real devices recorded on 2026-11-16, anonymised
// by testdata/anonymise.py (names, serials and addresses are made up)
// (testdata/walks, trimmed to the subtrees the profiles use).

type expect struct {
	profile      string
	interfaces   int
	minNeighbors int
	families     []string          // metric families that must be present
	inventory    map[string]string // exact inventory values
}

var cases = map[string]expect{
	"arista-eos": {profile: "arista-eos", interfaces: 116, minNeighbors: 60,
		families:  []string{"if_in_octets", "if_out_octets", "if_oper_status", "if_speed_bps", "cpu_load_percent", "storage_used_bytes", "sensor_value", "sensor_threshold_high_critical"},
		inventory: map[string]string{"model": "DCS-7050QX-32S", "os_version": "4.28.9M", "serial": "JPE27911220"}},
	"fortigate": {profile: "fortigate", interfaces: 42, minNeighbors: 1,
		families:  []string{"cpu_usage_percent", "memory_usage_percent", "firewall_sessions", "vpn_tunnel_status", "hw_sensor_alarm", "ha_member_sync_status", "if_in_octets"},
		inventory: map[string]string{"model": "FGT_120G", "os_version": "7.4.9", "ha_mode": "active-passive", "serial": "FG19238144196462"}},
	"sophos-sfos": {profile: "sophos-sfos", interfaces: 30,
		families:  []string{"memory_usage_percent", "disk_usage_percent", "live_users", "cpu_load_percent", "if_in_octets"},
		inventory: map[string]string{"model": "XGS126_XN02_SFOS"}},
	"aruba-instant-on": {profile: "aruba-instant-on", interfaces: 90, minNeighbors: 2,
		families:  []string{"if_in_octets", "if_oper_status"},
		inventory: map[string]string{"model": "JL685A", "os_version": "2.6.0.0"}},
	"tplink-jetstream": {profile: "tplink-jetstream", interfaces: 55, families: []string{"if_in_octets"}},
	"tplink-omada":     {profile: "tplink-jetstream", interfaces: 32, families: []string{"if_in_octets"}},
}

func registry(t *testing.T) *profile.Registry {
	t.Helper()
	reg, err := profile.Load(profiles.FS)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestProfilesAgainstRecordedDevices(t *testing.T) {
	reg := registry(t)
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			f, err := snmp.LoadFixture(filepath.Join("..", "testdata", "walks", name+".walk"))
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			sys, err := collect.Identify(ctx, f)
			if err != nil {
				t.Fatal(err)
			}
			p := reg.Detect(sys.ObjectID, sys.Descr)
			if p.Name != want.profile {
				t.Fatalf("detected profile %q, want %q (sysObjectID %s)", p.Name, want.profile, sys.ObjectID)
			}
			r := collect.Run(ctx, f, p, collect.Options{Inventory: true})
			if len(r.Errors) > 0 {
				t.Errorf("errors: %v", r.Errors)
			}
			if len(r.Interfaces) != want.interfaces {
				t.Errorf("interfaces = %d, want %d", len(r.Interfaces), want.interfaces)
			}
			if len(r.Neighbors) < want.minNeighbors {
				t.Errorf("neighbors = %d, want >= %d", len(r.Neighbors), want.minNeighbors)
			}
			for _, n := range r.Neighbors {
				if n.LocalPort == "" {
					t.Errorf("neighbor with empty local port: %+v", n)
				}
			}
			fams := map[string]int{}
			for _, s := range r.Samples {
				fams[s.Name]++
				if math.IsNaN(s.Value) || math.IsInf(s.Value, 0) {
					t.Errorf("%s has non-finite value", s.Name)
				}
				if strings.HasPrefix(s.Name, "if_") && s.Labels["ifname"] == "" {
					t.Errorf("%s without ifname label", s.Name)
				}
			}
			for _, fam := range want.families {
				if fams[fam] == 0 {
					t.Errorf("missing metric family %s", fam)
				}
			}
			for k, v := range want.inventory {
				if r.Inventory[k] != v {
					t.Errorf("inventory[%s] = %q, want %q", k, r.Inventory[k], v)
				}
			}
		})
	}
}

// Every interface counter must come from the 64-bit table when the device has it.
func TestHighCapacityCountersPreferred(t *testing.T) {
	reg := registry(t)
	f, err := snmp.LoadFixture("../testdata/walks/arista-eos.walk")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := reg.Get("arista-eos")
	r := collect.Run(context.Background(), f, p, collect.Options{Inventory: true})
	hc := 0
	for _, it := range r.Interfaces {
		if it.HighCap {
			hc++
		}
	}
	if hc != len(r.Interfaces) {
		t.Errorf("only %d/%d interfaces used HC counters", hc, len(r.Interfaces))
	}
	var max float64
	for _, s := range r.Samples {
		if s.Name == "if_in_octets" && s.Value > max {
			max = s.Value
		}
	}
	if max < 1<<32 {
		t.Errorf("largest in_octets %v fits in 32 bits; HC counters not used", max)
	}
}

// Arista optics: entPhySensor scale=milli(8), precision=4 -> 6485 = 0.6485 mW.
func TestEntitySensorScaling(t *testing.T) {
	if got := collect.SensorFactor(8, 4) * 6485; math.Abs(got-0.0006485) > 1e-12 {
		t.Errorf("scaled = %v, want 0.0006485 W", got)
	}
	reg := registry(t)
	f, _ := snmp.LoadFixture("../testdata/walks/arista-eos.walk")
	p, _ := reg.Get("arista-eos")
	r := collect.Run(context.Background(), f, p, collect.Options{})
	for _, s := range r.Samples {
		if s.Name == "sensor_value" && s.Labels["name"] == "Cpu temp sensor" {
			if s.Value < 20 || s.Value > 100 {
				t.Errorf("CPU temperature %v C is implausible", s.Value)
			}
			return
		}
	}
	t.Error("Cpu temp sensor not found")
}

// FortiGate subtrees that return genErr must be skipped, not fail the poll.
func TestSkipRootsAvoidAgentErrors(t *testing.T) {
	reg := registry(t)
	f, _ := snmp.LoadFixture("../testdata/walks/fortigate.walk")
	f.FailRoots = []string{"1.3.6.1.4.1.12356.101.5", "1.3.6.1.4.1.12356.101.7"}
	p, _ := reg.Get("fortigate")
	r := collect.Run(context.Background(), f, p, collect.Options{Inventory: true})
	if len(r.Errors) != 0 {
		t.Errorf("unexpected errors: %v", r.Errors)
	}
}

// A fast poll must not walk inventory-only tables.
func TestIntervalClasses(t *testing.T) {
	reg := registry(t)
	f, _ := snmp.LoadFixture("../testdata/walks/arista-eos.walk")
	p, _ := reg.Get("arista-eos")
	r := collect.Run(context.Background(), f, p, collect.Options{Classes: map[string]bool{profile.Fast: true}})
	for _, s := range r.Samples {
		if strings.HasPrefix(s.Name, "sensor_threshold") || s.Name == "if_info" {
			t.Fatalf("fast poll collected %s", s.Name)
		}
	}
	if len(r.Interfaces) != 0 || len(r.Neighbors) != 0 {
		t.Error("fast poll collected inventory")
	}
}

func TestGenericFallback(t *testing.T) {
	reg := registry(t)
	if p := reg.Detect("1.3.6.1.4.1.99999.1", "Some Unknown Box"); p.Name != "generic" {
		t.Errorf("got %s, want generic", p.Name)
	}
	if p := reg.Detect("0.3.0.6.0.1.0.4", "JetStream 48-Port Gigabit L2+ Managed Switch"); p.Name != "tplink-jetstream" {
		t.Errorf("JetStream with broken sysObjectID detected as %s", p.Name)
	}
}

// Profile alert expressions must reference metric families the profile produces.
func TestProfileAlertsReferenceKnownMetrics(t *testing.T) {
	reg := registry(t)
	for _, name := range reg.Names() {
		p, _ := reg.Get(name)
		for _, a := range p.Alerts {
			if !strings.Contains(a.Expr, "beacon_") {
				t.Errorf("%s alert %q does not use a beacon_ metric", name, a.Name)
			}
		}
	}
}
