package main

// Network devices: switches, firewalls and other gear this agent polls over
// SNMP for its site. Sentinel assigns devices to an agent that can reach
// them; their list (with credentials) arrives in the config and is kept in
// memory only. Each poll goes into the spool as its own batch, so a device's
// data survives an ingest outage like the server's own.
//
// Per device, on interval classes from its vendor profile:
//   - fast (30s): interface counters and status
//   - normal (60s): health (CPU, memory, sensors, VPNs)
//   - slow (5m): thresholds and rarely changing tables
//   - inventory (6h, at start, and after a reboot): system group,
//     interface metadata, LLDP neighbours, inventory fields

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"math"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/AlzyWelzy/sentinel/netmon/collect"
	"github.com/AlzyWelzy/sentinel/netmon/profile"
	"github.com/AlzyWelzy/sentinel/netmon/profiles"
	"github.com/AlzyWelzy/sentinel/netmon/snmp"
	"github.com/AlzyWelzy/sentinel/proto"
)

const (
	netFast        = 30 * time.Second
	netNormal      = 60 * time.Second
	netSlow        = 5 * time.Minute
	netInventory   = 6 * time.Hour
	netPollTimeout = 2 * time.Minute
	netConcurrency = 8 // devices polled at once
)

type netPoller struct {
	reg  *profile.Registry
	sink func(proto.Batch) // the spool
	log  *slog.Logger
	sem  chan struct{}

	mu         sync.Mutex
	running    map[string]*netDevice
	discovered map[string]bool // discoveries started (each runs once)
}

type netDevice struct {
	hash   [32]byte
	cancel context.CancelFunc
}

// netMaxSamplesPerBatch keeps one device's poll under ingest's per-request
// limit (100k samples): a big chassis is spooled as several batches.
const netMaxSamplesPerBatch = 40_000

func newNetPoller(sink func(proto.Batch), log *slog.Logger) (*netPoller, error) {
	reg, err := profile.Load(profiles.FS)
	if err != nil {
		return nil, err
	}
	split := func(b proto.Batch) {
		for len(b.Samples) > netMaxSamplesPerBatch {
			sink(proto.Batch{TimestampMs: b.TimestampMs, Samples: b.Samples[:netMaxSamplesPerBatch]})
			b.Samples = b.Samples[netMaxSamplesPerBatch:]
		}
		sink(b) // the poll's state rides with the last part
	}
	return &netPoller{reg: reg, sink: split, log: log, sem: make(chan struct{}, netConcurrency), running: map[string]*netDevice{}}, nil
}

// set starts polling new devices, stops removed ones and restarts changed
// ones (address, credential or pinned profile).
func (n *netPoller) set(ctx context.Context, devices []proto.NetworkDevice) {
	n.mu.Lock()
	defer n.mu.Unlock()
	want := map[string]bool{}
	for _, d := range devices {
		want[d.ID] = true
		b, _ := json.Marshal(d)
		h := sha256.Sum256(b)
		if cur, ok := n.running[d.ID]; ok {
			if cur.hash == h {
				continue
			}
			cur.cancel()
		}
		dctx, cancel := context.WithCancel(ctx)
		n.running[d.ID] = &netDevice{hash: h, cancel: cancel}
		if d.Credential.Version == "proxmox" {
			go n.runProxmox(dctx, d)
		} else {
			go n.run(dctx, d)
		}
	}
	for id, cur := range n.running {
		if !want[id] {
			cur.cancel()
			delete(n.running, id)
		}
	}
}

func jitterUpTo(d time.Duration) time.Duration { return time.Duration(rand.Int64N(int64(d))) }

// run owns one device: it schedules the interval classes, keeps the SNMP
// session, and re-runs the inventory after a reboot.
func (n *netPoller) run(ctx context.Context, d proto.NetworkDevice) {
	every := map[string]time.Duration{profile.Fast: netFast, profile.Normal: netNormal, profile.Slow: netSlow}
	first := time.Now().Add(jitterUpTo(5 * time.Second))
	next := map[string]time.Time{profile.Fast: first, profile.Normal: first, profile.Slow: first}
	nextInv := first
	var sess *snmp.Client
	var prof *profile.Profile
	var lastUptime float64
	defer func() {
		if sess != nil {
			sess.Close()
		}
	}()
	for {
		wake := nextInv
		for _, t := range next {
			if t.Before(wake) {
				wake = t
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(wake)):
		}
		now := time.Now()
		classes := map[string]bool{}
		for cl, t := range next {
			if !now.Before(t) {
				classes[cl] = true
				next[cl] = t.Add(every[cl])
				if next[cl].Before(now) { // a slow device fell behind: don't burst
					next[cl] = now.Add(every[cl])
				}
			}
		}
		inventory := !now.Before(nextInv)
		if inventory {
			nextInv = now.Add(netInventory)
			classes = nil // everything
		}
		select {
		case n.sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		batch, up, uptime, newSess, newProf := n.poll(ctx, d, sess, prof, classes, inventory)
		<-n.sem
		sess, prof = newSess, newProf
		if !up && sess != nil {
			sess.Close() // re-dial next time: the agent may have restarted
			sess = nil
		}
		if up {
			if lastUptime > 0 && uptime < lastUptime && !inventory {
				nextInv = time.Now() // rebooted: interfaces may have changed
			}
			lastUptime = uptime
		}
		if ctx.Err() == nil {
			n.sink(batch)
		}
	}
}

func (n *netPoller) poll(ctx context.Context, d proto.NetworkDevice, sess *snmp.Client, prof *profile.Profile, classes map[string]bool, inventory bool) (b proto.Batch, up bool, uptime float64, _ *snmp.Client, _ *profile.Profile) {
	start := time.Now()
	b.TimestampMs = start.UnixMilli()
	p := proto.NetworkPoll{DeviceID: d.ID, Full: inventory}
	defer func() {
		p.DurationMs = time.Since(start).Milliseconds()
		b.Network = []proto.NetworkPoll{p}
		b.Samples = append(b.Samples, proto.Sample{Name: "sentinel_net_snmp_up", Labels: map[string]string{"device_id": d.ID}, Value: boolFloat(up)},
			proto.Sample{Name: "sentinel_net_poll_duration_seconds", Labels: map[string]string{"device_id": d.ID}, Value: time.Since(start).Seconds()})
	}()
	ctx, cancel := context.WithTimeout(ctx, netPollTimeout)
	defer cancel()
	cred := snmp.Credential{
		Version: d.Credential.Version, Community: d.Credential.Community, Username: d.Credential.Username,
		AuthProtocol: d.Credential.AuthProtocol, AuthPassword: d.Credential.AuthPassword,
		PrivProtocol: d.Credential.PrivProtocol, PrivPassword: d.Credential.PrivPassword, Context: d.Credential.Context,
	}
	dial := func(pr *profile.Profile) (*snmp.Client, error) {
		var o snmp.Options
		if pr != nil {
			o.MaxRepetitions, o.UseGetNext = pr.SNMP.MaxRepetitions, pr.SNMP.UseGetNext
		}
		return snmp.Dial(d.Address, cred, o)
	}
	if prof == nil || inventory {
		if d.Profile != "" {
			if pr, ok := n.reg.Get(d.Profile); ok {
				prof = pr
			}
		}
		if d.Profile == "" || prof == nil {
			probe, err := dial(nil)
			if err != nil {
				p.Error = err.Error()
				return b, false, 0, sess, prof
			}
			sys, err := collect.Identify(ctx, probe)
			probe.Close()
			if err != nil {
				p.Error = snmpError(err)
				return b, false, 0, sess, prof
			}
			detected := n.reg.Detect(sys.ObjectID, sys.Descr)
			if prof == nil || prof.Name != detected.Name {
				if sess != nil {
					sess.Close()
					sess = nil
				}
				prof = detected
			}
		}
	}
	if sess == nil {
		s, err := dial(prof)
		if err != nil {
			p.Error = err.Error()
			return b, false, 0, nil, prof
		}
		sess = s
	}
	res := collect.Run(ctx, sess, prof, collect.Options{Classes: classes, Inventory: inventory})
	p.Profile = res.Profile
	for _, e := range res.Errors {
		if strings.HasPrefix(e, "system:") {
			p.Error = snmpError(errorString(strings.TrimSpace(strings.TrimPrefix(e, "system:"))))
			return b, false, 0, sess, prof
		}
	}
	p.OK = true
	if len(res.Errors) > 0 {
		// Some tables failed (genErr, a timeout on a slow subtree); the rest
		// is good. Say which, so the device page can show it.
		p.Error = strings.Join(res.Errors, "; ")
		if len(p.Error) > 1000 {
			p.Error = p.Error[:1000]
		}
	}
	sys := res.System
	p.System = &proto.NetworkSystem{Descr: sys.Descr, ObjectID: sys.ObjectID, Name: sys.Name, Contact: sys.Contact,
		Location: sys.Location, UptimeSec: sys.UptimeSec, Vendor: prof.Vendor}
	if inventory {
		p.Inventory = res.Inventory
		for _, i := range res.Interfaces {
			p.Interfaces = append(p.Interfaces, proto.NetworkInterface{Index: i.Index, Name: i.Name, Descr: i.Descr,
				Alias: i.Alias, Type: i.Type, SpeedBps: i.SpeedBps, MTU: i.MTU, MAC: i.MAC, AdminUp: i.AdminUp, OperStatus: i.OperStatus})
		}
		for _, nb := range res.Neighbors {
			p.Neighbors = append(p.Neighbors, proto.NetworkNeighbor{LocalPort: nb.LocalPort, RemoteSysName: nb.RemoteSysName,
				RemotePortID: nb.RemotePortID, RemotePortDesc: nb.RemotePortDesc, RemoteChassis: nb.RemoteChassis, RemoteMgmtAddr: nb.RemoteMgmtAddr})
		}
	}
	b.Samples = netSamples(d.ID, res.Samples)
	return b, true, sys.UptimeSec, sess, prof
}

// netSamples names device samples like the rest of Sentinel's:
// sentinel_net_<name>, counters ending _total, labelled with the device.
func netSamples(deviceID string, in []collect.Sample) []proto.Sample {
	out := make([]proto.Sample, 0, len(in))
	for _, s := range in {
		if math.IsNaN(s.Value) || math.IsInf(s.Value, 0) {
			continue
		}
		name := "sentinel_net_" + s.Name
		if s.Counter && !strings.HasSuffix(name, "_total") {
			name += "_total"
		}
		labels := make(map[string]string, len(s.Labels)+1)
		for k, v := range s.Labels {
			labels[k] = v
		}
		labels["device_id"] = deviceID
		out = append(out, proto.Sample{Name: name, Labels: labels, Value: s.Value})
	}
	return out
}

type errorString string

func (e errorString) Error() string { return string(e) }

// snmpError says what a failed poll most likely means.
func snmpError(err error) string {
	s := err.Error()
	if strings.Contains(s, "timeout") || strings.Contains(s, "no system group") {
		return "No SNMP answer: the device is down or unreachable from this server, SNMP is off, or the community / v3 user is wrong (" + s + ")"
	}
	return s
}

func boolFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
