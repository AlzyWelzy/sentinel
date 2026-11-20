package main

// Proxmox VE clusters, polled through the REST API with an API token
// (Datacenter › Permissions › API Tokens; the PVEAuditor role is enough).
// One call to /cluster/resources returns every node, guest and storage;
// /cluster/status adds quorum. The device's address is host[:port], 8006
// unless given.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

type pveResource struct {
	Type      string  `json:"type"` // node, qemu, lxc, storage
	Node      string  `json:"node"`
	Name      string  `json:"name"`
	Storage   string  `json:"storage"`
	Status    string  `json:"status"`
	VMID      int     `json:"vmid"`
	Template  int     `json:"template"`
	CPU       float64 `json:"cpu"`
	MaxCPU    float64 `json:"maxcpu"`
	Mem       float64 `json:"mem"`
	MaxMem    float64 `json:"maxmem"`
	Disk      float64 `json:"disk"`
	MaxDisk   float64 `json:"maxdisk"`
	Uptime    float64 `json:"uptime"`
	NetIn     float64 `json:"netin"`
	NetOut    float64 `json:"netout"`
	DiskRead  float64 `json:"diskread"`
	DiskWrite float64 `json:"diskwrite"`
	Shared    int     `json:"shared"`
}

type pveClusterStatus struct {
	Type    string `json:"type"` // cluster, node
	Name    string `json:"name"`
	Quorate int    `json:"quorate"`
	Online  int    `json:"online"`
	Nodes   int    `json:"nodes"`
	Version int    `json:"version"`
}

func pveBaseURL(address string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host, port = strings.Trim(address, "[]"), "8006"
	}
	return "https://" + net.JoinHostPort(host, port) + "/api2/json"
}

// pollProxmox reads the cluster once. ok is false when the API didn't answer
// or refused the token.
func pollProxmox(ctx context.Context, d proto.NetworkDevice, client *http.Client) (b proto.Batch) {
	start := time.Now()
	b.TimestampMs = start.UnixMilli()
	p := proto.NetworkPoll{DeviceID: d.ID, Profile: "proxmox"}
	defer func() {
		p.DurationMs = time.Since(start).Milliseconds()
		b.Network = []proto.NetworkPoll{p}
		b.Samples = append(b.Samples, proto.Sample{Name: "sentinel_net_snmp_up", Labels: map[string]string{"device_id": d.ID}, Value: boolFloat(p.OK)})
	}()
	c := d.Credential
	if c.TokenUser == "" || c.TokenName == "" || c.TokenValue == "" {
		p.Error = "The Proxmox credential needs an API token (user, token name, secret)"
		return b
	}
	auth := fmt.Sprintf("PVEAPIToken=%s!%s=%s", c.TokenUser, c.TokenName, c.TokenValue)
	base := pveBaseURL(d.Address)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var resources []pveResource
	if err := pveGet(ctx, client, base+"/cluster/resources", auth, &resources); err != nil {
		p.Error = err.Error()
		return b
	}
	var status []pveClusterStatus
	cluster := ""
	if err := pveGet(ctx, client, base+"/cluster/status", auth, &status); err == nil {
		for _, s := range status {
			if s.Type == "cluster" {
				cluster = s.Name
				b.Samples = append(b.Samples,
					proto.Sample{Name: "sentinel_net_pve_cluster_quorate", Value: float64(s.Quorate), Labels: map[string]string{"device_id": d.ID, "cluster": s.Name}},
					proto.Sample{Name: "sentinel_net_pve_cluster_nodes", Value: float64(s.Nodes), Labels: map[string]string{"device_id": d.ID, "cluster": s.Name}})
			}
		}
	}
	nodes := 0
	for _, r := range resources {
		if r.Type == "node" {
			nodes++
			if cluster == "" {
				cluster = r.Node // a single node, no cluster
			}
		}
	}
	p.OK = true
	p.System = &proto.NetworkSystem{Name: cluster, Vendor: "Proxmox", Descr: fmt.Sprintf("Proxmox VE, %d node%s", nodes, map[bool]string{true: "", false: "s"}[nodes == 1])}
	b.Samples = append(b.Samples, pveSamples(d.ID, resources)...)
	return b
}

func pveGet(ctx context.Context, client *http.Client, url, auth string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("User-Agent", "sentinel-agent/"+version)
	resp, err := client.Do(req)
	if err != nil {
		var certErr *tls.CertificateVerificationError
		if errors.As(err, &certErr) {
			return errors.New("The Proxmox certificate isn't trusted (self-signed): turn on 'accept a self-signed certificate' in the credential, or install a trusted one")
		}
		return fmt.Errorf("Proxmox API unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("Proxmox refused the API token (%s): check the token and that it has the PVEAuditor role", resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("Proxmox API %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&env); err != nil {
		return fmt.Errorf("Proxmox API: %w", err)
	}
	return json.Unmarshal(env.Data, out)
}

// pveSamples turns /cluster/resources into metrics. Templates are skipped;
// stopped guests and offline nodes only report that they're down (their
// usage numbers are stale).
func pveSamples(deviceID string, rs []pveResource) []proto.Sample {
	var out []proto.Sample
	add := func(name string, l map[string]string, v float64) {
		labels := map[string]string{"device_id": deviceID}
		for k, x := range l {
			labels[k] = x
		}
		out = append(out, proto.Sample{Name: "sentinel_net_pve_" + name, Labels: labels, Value: v})
	}
	for _, r := range rs {
		var l map[string]string
		up := 0.0
		switch r.Type {
		case "node":
			l = map[string]string{"type": "node", "node": r.Node}
			if r.Status == "online" {
				up = 1
			}
		case "qemu", "lxc":
			if r.Template == 1 {
				continue
			}
			l = map[string]string{"type": r.Type, "node": r.Node, "vmid": strconv.Itoa(r.VMID), "name": r.Name}
			if r.Status == "running" {
				up = 1
			}
		case "storage":
			l = map[string]string{"type": "storage", "node": r.Node, "storage": r.Storage}
			if r.Shared == 1 {
				l["shared"] = "1" // listed once per node
			}
			if r.Status == "available" {
				up = 1
			}
		default:
			continue
		}
		add("up", l, up)
		if r.Type == "storage" {
			if r.MaxDisk > 0 {
				add("disk_used_bytes", l, r.Disk)
				add("disk_size_bytes", l, r.MaxDisk)
			}
			continue
		}
		if up == 0 {
			continue
		}
		add("cpu_ratio", l, r.CPU)
		add("cpus", l, r.MaxCPU)
		add("memory_used_bytes", l, r.Mem)
		add("memory_size_bytes", l, r.MaxMem)
		add("uptime_seconds", l, r.Uptime)
		if r.Type == "node" {
			add("disk_used_bytes", l, r.Disk)
			add("disk_size_bytes", l, r.MaxDisk)
			continue
		}
		add("network_receive_bytes_total", l, r.NetIn)
		add("network_transmit_bytes_total", l, r.NetOut)
		add("disk_read_bytes_total", l, r.DiskRead)
		add("disk_written_bytes_total", l, r.DiskWrite)
	}
	return out
}

func newPVEClient(insecure bool) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecure} //nolint:gosec // opt-in per credential: Proxmox installs a self-signed certificate
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

// runProxmox polls a cluster every minute.
func (n *netPoller) runProxmox(ctx context.Context, d proto.NetworkDevice) {
	client := newPVEClient(d.Credential.InsecureTLS)
	defer client.CloseIdleConnections()
	timer := time.NewTimer(jitterUpTo(5 * time.Second))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		select {
		case n.sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		b := pollProxmox(ctx, d, client)
		<-n.sem
		if ctx.Err() == nil {
			n.sink(b)
		}
		timer.Reset(netNormal)
	}
}
