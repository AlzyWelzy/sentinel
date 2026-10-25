package plugins

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func init() { allowUserOwned = true }

func TestParseNginx(t *testing.T) {
	s, err := parseNginx("Active connections: 3 \nserver accepts handled requests\n 10 9 42 \nReading: 0 Writing: 1 Waiting: 2 \n")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, x := range s {
		got[x.Name+x.Labels["state"]] = x.Value
	}
	if got["pulsegrid_nginx_requests_total"] != 42 || got["pulsegrid_nginx_connections_active"] != 3 || got["pulsegrid_nginx_connectionswaiting"] != 2 {
		t.Fatalf("%v", got)
	}
}

func TestParseApache(t *testing.T) {
	s, err := parseApache("Total Accesses: 100\nBusyWorkers: 2\nIdleWorkers: 8\nScoreboard: __W\n")
	if err != nil || len(s) != 3 {
		t.Fatalf("%v %v", s, err)
	}
}

func TestParseRedisInfo(t *testing.T) {
	s := parseRedisInfo("# Clients\r\nconnected_clients:5\r\nrole:master\r\ndb0:keys=10,expires=1,avg_ttl=0\r\ndb1:keys=5,expires=0\r\n")
	got := map[string]float64{}
	for _, x := range s {
		got[x.Name] = x.Value
	}
	if got["pulsegrid_redis_clients"] != 5 || got["pulsegrid_redis_keys"] != 15 || got["pulsegrid_redis_is_master"] != 1 {
		t.Fatalf("%v", got)
	}
}

func TestParseExposition(t *testing.T) {
	text := `# HELP x
# TYPE http_requests_total counter
http_requests_total{method="get",code="200",tenant_id="evil"} 1027 1395066363000
queue_depth 7
weird{a="x\"y",} 1.5
bad line here
`
	s, err := ParseExposition(text, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 3 {
		t.Fatalf("got %d samples: %+v", len(s), s)
	}
	if s[0].Name != "pulsegrid_custom_http_requests_total" || s[0].Labels["method"] != "get" || s[0].Labels["tenant_id"] != "" {
		t.Fatalf("%+v", s[0])
	}
	if s[2].Labels["a"] != `x"y` {
		t.Fatalf("%+v", s[2])
	}
	if _, err := ParseExposition("a 1\nb 2\nc 3\n", nil, 2); err == nil {
		t.Fatal("limit not enforced")
	}
}

func TestLoadAndScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix commands and file modes; Windows relies on the installer's folder ACLs")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "m.sh")
	os.WriteFile(script, []byte("#!/bin/sh\necho 'jobs_waiting{queue=\"mail\"} 4'\n"), 0o755)
	os.WriteFile(filepath.Join(dir, "jobs.conf"), []byte("# queue\ntype = script\ncommand = "+script+"\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "bad.conf"), []byte("type = oracle\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "open.conf"), []byte("type = redis\n"), 0o666)
	os.Chmod(filepath.Join(dir, "open.conf"), 0o666)
	list, errs := Load(dir)
	if len(list) != 1 || len(errs) != 2 {
		t.Fatalf("list=%v errs=%v", list, errs)
	}
	res := Collect(context.Background(), list)
	if !res[0].Status.OK {
		t.Fatal(res[0].Status.Error)
	}
	var found bool
	for _, s := range res[0].Samples {
		if s.Name == "pulsegrid_custom_jobs_waiting" && s.Value == 4 && s.Labels["plugin"] == "jobs" && s.Labels["queue"] == "mail" {
			found = true
		}
	}
	if !found {
		t.Fatalf("%+v", res[0].Samples)
	}
}

func TestRedisDown(t *testing.T) {
	res := Collect(context.Background(), []Config{{Name: "r", Type: "redis", Settings: map[string]string{"address": "127.0.0.1:1"}}})
	if res[0].Status.OK || !strings.Contains(res[0].Status.Error, "refused") {
		t.Fatalf("%+v", res[0].Status)
	}
	last := res[0].Samples[len(res[0].Samples)-1]
	if last.Name != "pulsegrid_plugin_up" || last.Value != 0 {
		t.Fatalf("%+v", last)
	}
}
