// Package plugins collects application metrics (MySQL, PostgreSQL, Redis,
// Nginx, Apache, Docker, Prometheus endpoints and local scripts) from plugin
// files the server's administrator writes in the agent's config directory.
//
// Plugins are configured only on the server, never pushed from the
// dashboard: they hold database passwords, and a script plugin runs code.
// The directory and files must not be writable by the agent's own user, so a
// compromised agent can't add plugins of its own.
//
// One plugin per file, <config dir>/plugins.d/<name>.conf:
//
//	type = mysql
//	dsn = monitor:secret@tcp(127.0.0.1:3306)/
package plugins

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

const pluginTimeout = 10 * time.Second

// Config is one plugin file: its name (the file name) and settings.
type Config struct {
	Name     string
	Type     string
	Settings map[string]string
	Path     string
}

// collectFunc gathers one plugin's samples.
type collectFunc func(ctx context.Context, c Config) ([]proto.Sample, error)

var collectors = map[string]collectFunc{
	"mysql":      collectMySQL,
	"postgres":   collectPostgres,
	"redis":      collectRedis,
	"nginx":      collectNginx,
	"apache":     collectApache,
	"docker":     collectDocker,
	"prometheus": collectPrometheus,
	"script":     collectScript,
	"smart":      collectSmart,
	"ipmi":       collectIPMI,
	"lvm":        collectLVM,
	"snmp":       collectSNMP,
}

// Types lists the supported plugin types.
func Types() []string {
	var t []string
	for k := range collectors {
		t = append(t, k)
	}
	sort.Strings(t)
	return t
}

// Load reads every *.conf in dir. A missing directory means no plugins.
// Files that fail validation are returned as errors and skipped.
func Load(dir string) ([]Config, []error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, []error{err}
	}
	if err := CheckOwnership(dir); err != nil {
		return nil, []error{err}
	}
	var out []Config
	var errs []error
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		c, err := parseFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Name(), err))
			continue
		}
		out = append(out, c)
	}
	return out, errs
}

func parseFile(path string) (Config, error) {
	if err := CheckOwnership(path); err != nil {
		return Config{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	settings, err := ParseKV(f)
	if err != nil {
		return Config{}, err
	}
	c := Config{
		Name:     strings.TrimSuffix(filepath.Base(path), ".conf"),
		Type:     strings.ToLower(settings["type"]),
		Settings: settings,
		Path:     path,
	}
	if _, ok := collectors[c.Type]; !ok {
		return c, fmt.Errorf("unknown type %q (supported: %s)", c.Type, strings.Join(Types(), ", "))
	}
	return c, nil
}

// ParseKV reads "key = value" lines; # starts a comment line.
func ParseKV(r interface{ Read([]byte) (int, error) }) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key = value", n)
		}
		out[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return out, sc.Err()
}

// Result is one plugin run.
type Result struct {
	Status  proto.PluginStatus
	Samples []proto.Sample
}

// Collect runs every plugin concurrently. Each plugin's samples carry a
// plugin=<name> label so two MySQL servers stay apart.
func Collect(ctx context.Context, list []Config) []Result {
	out := make([]Result, len(list))
	done := make(chan struct{}, len(list))
	for i, c := range list {
		go func(i int, c Config) {
			defer func() { done <- struct{}{} }()
			cctx, cancel := context.WithTimeout(ctx, pluginTimeout)
			defer cancel()
			samples, err := collectors[c.Type](cctx, c)
			st := proto.PluginStatus{Name: c.Name, Type: c.Type, OK: err == nil}
			if err != nil {
				st.Error = trim(err.Error(), 300)
			}
			for j := range samples {
				if samples[j].Labels == nil {
					samples[j].Labels = map[string]string{}
				}
				samples[j].Labels["plugin"] = c.Name
			}
			samples = append(samples, proto.Sample{
				Name: "sentinel_plugin_up", Value: boolValue(err == nil),
				Labels: map[string]string{"plugin": c.Name, "type": c.Type},
			})
			out[i] = Result{Status: st, Samples: samples}
		}(i, c)
	}
	for range list {
		<-done
	}
	return out
}

func sample(name string, v float64, labels ...string) proto.Sample {
	s := proto.Sample{Name: name, Value: v}
	if len(labels) > 0 {
		s.Labels = map[string]string{}
		for i := 0; i+1 < len(labels); i += 2 {
			s.Labels[labels[i]] = labels[i+1]
		}
	}
	return s
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func setting(c Config, key, fallback string) string {
	if v := c.Settings[key]; v != "" {
		return v
	}
	return fallback
}
