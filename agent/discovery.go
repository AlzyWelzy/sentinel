package main

// Network discovery: scan an address range once for devices answering SNMP
// with the given credential, and report what each one is. Progress goes
// out every few seconds; the last report is marked done. Ranges are capped
// by the API (1024 addresses); scans run 32 addresses at a time with short
// timeouts, so a /22 takes about a minute.

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/AlzyWelzy/pulsegrid-beyond/netmon/collect"
	"github.com/AlzyWelzy/pulsegrid-beyond/netmon/snmp"
	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

const (
	discoveryParallel = 32
	discoveryMax      = 1024
	discoveryReport   = 5 * time.Second
)

// rangeAddrs lists the addresses of an IPv4 range, without the network and
// broadcast addresses of ranges larger than /31.
func rangeAddrs(cidr string) ([]netip.Addr, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}
	p = p.Masked()
	hosts := p.Addr().Is4() && p.Bits() < 31 // has network and broadcast addresses
	a := p.Addr()
	if hosts {
		a = a.Next() // skip the network address
	}
	var out []netip.Addr
	whole := true
	for ; p.Contains(a); a = a.Next() {
		if len(out) == discoveryMax {
			whole = false // capped: the last one listed isn't the broadcast
			break
		}
		out = append(out, a)
	}
	if hosts && whole && len(out) > 0 {
		out = out[:len(out)-1] // the broadcast address
	}
	return out, nil
}

func (n *netPoller) discover(ctx context.Context, d proto.NetworkDiscovery) {
	addrs, err := rangeAddrs(d.CIDR)
	if err != nil {
		n.sink(proto.Batch{TimestampMs: time.Now().UnixMilli(), Discoveries: []proto.DiscoveryResult{{ID: d.ID, Done: true, Error: err.Error()}}})
		return
	}
	cred := snmp.Credential{Version: d.Credential.Version, Community: d.Credential.Community, Username: d.Credential.Username,
		AuthProtocol: d.Credential.AuthProtocol, AuthPassword: d.Credential.AuthPassword,
		PrivProtocol: d.Credential.PrivProtocol, PrivPassword: d.Credential.PrivPassword, Context: d.Credential.Context}
	port := d.Port
	if port == 0 {
		port = 161
	}
	var (
		mu      sync.Mutex
		found   []proto.DiscoveredDevice
		scanned int
	)
	report := func(done bool) {
		mu.Lock()
		r := proto.DiscoveryResult{ID: d.ID, Scanned: scanned, Total: len(addrs), Done: done, Found: append([]proto.DiscoveredDevice(nil), found...)}
		mu.Unlock()
		n.sink(proto.Batch{TimestampMs: time.Now().UnixMilli(), Discoveries: []proto.DiscoveryResult{r}})
	}
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(discoveryReport)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				report(false)
			}
		}
	}()
	sem := make(chan struct{}, discoveryParallel)
	var wg sync.WaitGroup
	for _, a := range addrs {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(a netip.Addr) {
			defer func() { <-sem; wg.Done() }()
			addr := a.String()
			target := addr
			if port != 161 {
				target = netip.AddrPortFrom(a, uint16(port)).String()
			}
			if dev, ok := n.probe(ctx, target, cred); ok {
				dev.Address = target
				mu.Lock()
				found = append(found, dev)
				mu.Unlock()
			}
			mu.Lock()
			scanned++
			mu.Unlock()
		}(a)
	}
	wg.Wait()
	close(stop)
	report(true)
}

// probe asks one address for its system group.
func (n *netPoller) probe(ctx context.Context, target string, cred snmp.Credential) (proto.DiscoveredDevice, bool) {
	s, err := snmp.Dial(target, cred, snmp.Options{Timeout: 1500 * time.Millisecond, Retries: 1})
	if err != nil {
		return proto.DiscoveredDevice{}, false
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	sys, err := collect.Identify(ctx, s)
	if err != nil {
		return proto.DiscoveredDevice{}, false
	}
	p := n.reg.Detect(sys.ObjectID, sys.Descr)
	descr := sys.Descr
	if len(descr) > 300 {
		descr = descr[:300]
	}
	return proto.DiscoveredDevice{SysName: sys.Name, SysDescr: descr, ObjectID: sys.ObjectID, Profile: p.Name, Vendor: p.Vendor}, true
}

// setDiscoveries starts each discovery once (by id) for as long as the
// agent runs.
func (n *netPoller) setDiscoveries(ctx context.Context, ds []proto.NetworkDiscovery) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.discovered == nil {
		n.discovered = map[string]bool{}
	}
	for _, d := range ds {
		if n.discovered[d.ID] {
			continue
		}
		n.discovered[d.ID] = true
		go n.discover(ctx, d)
	}
}
