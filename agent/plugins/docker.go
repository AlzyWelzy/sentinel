package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"

	"github.com/AlzyWelzy/sentinel/proto"
)

// maxContainers bounds the per-container stats calls (one HTTP request each).
const maxContainers = 100

// collectDocker reads the Engine API: socket = /var/run/docker.sock.
// The agent's user needs access to the socket (add it to the docker group).
func collectDocker(ctx context.Context, c Config) ([]proto.Sample, error) {
	sock := setting(c, "socket", defaultDockerSocket())
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			if strings.HasPrefix(sock, "tcp://") {
				return d.DialContext(ctx, "tcp", strings.TrimPrefix(sock, "tcp://"))
			}
			return dialDocker(ctx, sock)
		},
	}}
	var containers []struct {
		ID     string   `json:"Id"`
		Names  []string `json:"Names"`
		Image  string   `json:"Image"`
		State  string   `json:"State"`
		Status string   `json:"Status"`
	}
	if err := dockerGet(ctx, client, "/containers/json?all=true", &containers); err != nil {
		return nil, err
	}
	var out []proto.Sample
	states := map[string]float64{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, ct := range containers {
		states[ct.State]++
		name := strings.TrimPrefix(firstOr(ct.Names, ct.ID[:12]), "/")
		running := ct.State == "running"
		out = append(out, sample("sentinel_container_running", boolValue(running), "container", name, "image", trimImage(ct.Image)))
		if !running || i >= maxContainers {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(id, name string) {
			defer wg.Done()
			defer func() { <-sem }()
			s, err := containerStats(ctx, client, id, name)
			if err != nil {
				return
			}
			mu.Lock()
			out = append(out, s...)
			mu.Unlock()
		}(ct.ID, name)
	}
	wg.Wait()
	for st, n := range states {
		out = append(out, sample("sentinel_containers", n, "state", st))
	}
	return out, nil
}

func containerStats(ctx context.Context, client *http.Client, id, name string) ([]proto.Sample, error) {
	var s struct {
		CPUStats struct {
			CPUUsage struct {
				TotalUsage uint64 `json:"total_usage"`
			} `json:"cpu_usage"`
			SystemUsage uint64 `json:"system_cpu_usage"`
			OnlineCPUs  uint64 `json:"online_cpus"`
		} `json:"cpu_stats"`
		PreCPUStats struct {
			CPUUsage struct {
				TotalUsage uint64 `json:"total_usage"`
			} `json:"cpu_usage"`
			SystemUsage uint64 `json:"system_cpu_usage"`
		} `json:"precpu_stats"`
		MemoryStats struct {
			Usage uint64            `json:"usage"`
			Limit uint64            `json:"limit"`
			Stats map[string]uint64 `json:"stats"`
		} `json:"memory_stats"`
		Networks map[string]struct {
			RxBytes uint64 `json:"rx_bytes"`
			TxBytes uint64 `json:"tx_bytes"`
		} `json:"networks"`
	}
	// one-shot skips the 1s wait for a second sample (Engine API 1.41+);
	// precpu is then empty and CPU% is computed by the dashboard from the counter.
	if err := dockerGet(ctx, client, "/containers/"+id+"/stats?stream=false", &s); err != nil {
		return nil, err
	}
	l := []string{"container", name}
	var out []proto.Sample
	cpuDelta := float64(s.CPUStats.CPUUsage.TotalUsage) - float64(s.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(s.CPUStats.SystemUsage) - float64(s.PreCPUStats.SystemUsage)
	if sysDelta > 0 && cpuDelta >= 0 {
		cpus := float64(s.CPUStats.OnlineCPUs)
		if cpus == 0 {
			cpus = 1
		}
		out = append(out, sample("sentinel_container_cpu_percent", cpuDelta/sysDelta*cpus*100, l...))
	}
	out = append(out, sample("sentinel_container_cpu_seconds_total", float64(s.CPUStats.CPUUsage.TotalUsage)/1e9, l...))
	// Like `docker stats`: page cache that can be reclaimed isn't "used".
	mem := float64(s.MemoryStats.Usage)
	if cache, ok := s.MemoryStats.Stats["inactive_file"]; ok && float64(cache) < mem {
		mem -= float64(cache)
	}
	out = append(out, sample("sentinel_container_memory_bytes", mem, l...))
	if s.MemoryStats.Limit > 0 {
		out = append(out, sample("sentinel_container_memory_percent", mem/float64(s.MemoryStats.Limit)*100, l...))
	}
	var rx, tx float64
	for _, n := range s.Networks {
		rx += float64(n.RxBytes)
		tx += float64(n.TxBytes)
	}
	out = append(out,
		sample("sentinel_container_network_received_bytes_total", rx, l...),
		sample("sentinel_container_network_sent_bytes_total", tx, l...))
	return out, nil
}

func dockerGet(ctx context.Context, client *http.Client, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("docker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker %s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func defaultDockerSocket() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\docker_engine`
	}
	return "/var/run/docker.sock"
}

func firstOr(a []string, fallback string) string {
	if len(a) > 0 {
		return a[0]
	}
	return fallback
}

func trimImage(s string) string {
	if strings.HasPrefix(s, "sha256:") && len(s) > 19 {
		return s[:19]
	}
	return s
}
