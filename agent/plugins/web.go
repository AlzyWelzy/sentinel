package plugins

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/example-org/pulsegrid/proto"
)

var httpClient = &http.Client{Timeout: pluginTimeout}

func get(ctx context.Context, url string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// collectNginx reads stub_status: url = http://127.0.0.1/nginx_status
//
//	Active connections: 2
//	server accepts handled requests
//	 10 10 20
//	Reading: 0 Writing: 1 Waiting: 1
func collectNginx(ctx context.Context, c Config) ([]proto.Sample, error) {
	body, err := get(ctx, setting(c, "url", "http://127.0.0.1/nginx_status"), nil)
	if err != nil {
		return nil, err
	}
	return parseNginx(string(body))
}

func parseNginx(body string) ([]proto.Sample, error) {
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) < 4 || !strings.HasPrefix(lines[0], "Active connections:") {
		return nil, fmt.Errorf("not an nginx stub_status page")
	}
	var out []proto.Sample
	active, _ := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(lines[0], "Active connections:")), 64)
	out = append(out, sample("pulsegrid_nginx_connections_active", active))
	nums := strings.Fields(lines[2])
	if len(nums) == 3 {
		names := []string{"pulsegrid_nginx_connections_accepted_total", "pulsegrid_nginx_connections_handled_total", "pulsegrid_nginx_requests_total"}
		for i, n := range nums {
			if v, err := strconv.ParseFloat(n, 64); err == nil {
				out = append(out, sample(names[i], v))
			}
		}
	}
	f := strings.Fields(lines[3])
	for i := 0; i+1 < len(f); i += 2 {
		state := strings.ToLower(strings.TrimSuffix(f[i], ":"))
		if v, err := strconv.ParseFloat(f[i+1], 64); err == nil {
			out = append(out, sample("pulsegrid_nginx_connections", v, "state", state))
		}
	}
	return out, nil
}

// collectApache reads mod_status: url = http://127.0.0.1/server-status?auto
func collectApache(ctx context.Context, c Config) ([]proto.Sample, error) {
	body, err := get(ctx, setting(c, "url", "http://127.0.0.1/server-status?auto"), nil)
	if err != nil {
		return nil, err
	}
	return parseApache(string(body))
}

func parseApache(body string) ([]proto.Sample, error) {
	fields := map[string]string{
		"Total Accesses": "pulsegrid_apache_requests_total",
		"Total kBytes":   "pulsegrid_apache_sent_kilobytes_total",
		"BusyWorkers":    "pulsegrid_apache_workers_busy",
		"IdleWorkers":    "pulsegrid_apache_workers_idle",
		"Uptime":         "pulsegrid_apache_uptime_seconds",
		"ConnsTotal":     "pulsegrid_apache_connections",
	}
	var out []proto.Sample
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		if name, ok := fields[strings.TrimSpace(k)]; ok {
			if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
				out = append(out, sample(name, f))
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("not an Apache server-status?auto page")
	}
	return out, nil
}

// collectRedis speaks just enough RESP to run INFO:
// address = 127.0.0.1:6379, password = … (optional), username = … (ACL)
func collectRedis(ctx context.Context, c Config) ([]proto.Sample, error) {
	addr := setting(c, "address", "127.0.0.1:6379")
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	} else {
		conn.SetDeadline(time.Now().Add(pluginTimeout))
	}
	r := bufio.NewReader(conn)
	if pw := c.Settings["password"]; pw != "" {
		args := []string{"AUTH", pw}
		if u := c.Settings["username"]; u != "" {
			args = []string{"AUTH", u, pw}
		}
		if _, err := redisCmd(conn, r, args...); err != nil {
			return nil, fmt.Errorf("AUTH: %w", err)
		}
	}
	info, err := redisCmd(conn, r, "INFO")
	if err != nil {
		return nil, err
	}
	return parseRedisInfo(info), nil
}

func redisCmd(w io.Writer, r *bufio.Reader, args ...string) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return "", err
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	switch {
	case strings.HasPrefix(line, "+"):
		return line[1:], nil
	case strings.HasPrefix(line, "-"):
		return "", fmt.Errorf("%s", line[1:])
	case strings.HasPrefix(line, "$"):
		n, err := strconv.Atoi(line[1:])
		if err != nil || n < 0 || n > 16<<20 {
			return "", fmt.Errorf("bad reply length")
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return string(buf[:n]), nil
	}
	return "", fmt.Errorf("unexpected reply %q", line)
}

var redisFields = map[string]string{
	"connected_clients":           "pulsegrid_redis_clients",
	"blocked_clients":             "pulsegrid_redis_blocked_clients",
	"used_memory":                 "pulsegrid_redis_memory_used_bytes",
	"maxmemory":                   "pulsegrid_redis_memory_max_bytes",
	"mem_fragmentation_ratio":     "pulsegrid_redis_memory_fragmentation_ratio",
	"total_commands_processed":    "pulsegrid_redis_commands_total",
	"total_connections_received":  "pulsegrid_redis_connections_total",
	"keyspace_hits":               "pulsegrid_redis_keyspace_hits_total",
	"keyspace_misses":             "pulsegrid_redis_keyspace_misses_total",
	"evicted_keys":                "pulsegrid_redis_evicted_keys_total",
	"expired_keys":                "pulsegrid_redis_expired_keys_total",
	"rejected_connections":        "pulsegrid_redis_rejected_connections_total",
	"connected_slaves":            "pulsegrid_redis_replicas",
	"master_last_io_seconds_ago":  "pulsegrid_redis_master_last_io_seconds",
	"rdb_changes_since_last_save": "pulsegrid_redis_changes_since_save",
	"uptime_in_seconds":           "pulsegrid_redis_uptime_seconds",
}

func parseRedisInfo(info string) []proto.Sample {
	var out []proto.Sample
	keys := 0.0
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if name, ok := redisFields[k]; ok {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				out = append(out, sample(name, f))
			}
		}
		if strings.HasPrefix(k, "db") {
			// db0:keys=1,expires=0,avg_ttl=0
			for _, kv := range strings.Split(v, ",") {
				if n, ok := strings.CutPrefix(kv, "keys="); ok {
					if f, err := strconv.ParseFloat(n, 64); err == nil {
						keys += f
					}
				}
			}
		}
		if k == "role" {
			out = append(out, sample("pulsegrid_redis_is_master", boolValue(v == "master")))
		}
	}
	out = append(out, sample("pulsegrid_redis_keys", keys))
	return out
}
