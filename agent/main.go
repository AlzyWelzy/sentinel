// Command pulsegrid-agent collects host metrics and pushes them to Pulsegrid.
//
//	pulsegrid-agent register --url <ingest url> --key <install key>
//	pulsegrid-agent run
//	pulsegrid-agent update   (root, from a systemd timer)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/example-org/pulsegrid/agent/collector"
	"github.com/example-org/pulsegrid/proto"
)

// Set at build time: -ldflags "-X main.version=1.2.3"
var version = "dev"

const (
	defaultInterval = 30
	// Alert rules decide which processes and services agents watch, so a new
	// rule should reach the agent within a couple of minutes.
	configRefreshEvery = 2 * time.Minute
	// Hostname, IPs and OS version rarely change; re-read them now and then.
	metaRefreshEvery  = 10 * time.Minute
	maxBatchesPerPush = 20
	spoolMaxBatches   = 2880 // 24h at 30s
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	var err error
	switch os.Args[1] {
	case "register":
		err = cmdRegister(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:], log)
	case "update":
		err = cmdUpdate(os.Args[2:])
	case "version":
		fmt.Println(version)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pulsegrid-agent:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: pulsegrid-agent register --url URL --key KEY [--tags a,b] [--state-dir DIR]")
	fmt.Fprintln(os.Stderr, "       pulsegrid-agent run [--state-dir DIR] [--pidfile FILE]")
	fmt.Fprintln(os.Stderr, "       pulsegrid-agent update [--state-dir DIR] [--restart SERVICE]")
	fmt.Fprintln(os.Stderr, "       pulsegrid-agent version")
	os.Exit(2)
}

func cmdRegister(args []string) error {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	url := fs.String("url", "", "Pulsegrid ingest URL")
	key := fs.String("key", "", "install key from the dashboard")
	tags := fs.String("tags", "", "comma-separated tags to add to this server, e.g. web,production")
	stateDir := fs.String("state-dir", defaultStateDir(), "where the agent keeps its state")
	fs.Parse(args)
	if *url == "" || *key == "" {
		return errors.New("--url and --key are required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	info, err := collector.Info(ctx)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		return err
	}
	if info.MachineID == "" {
		// No stable id from the OS: use one generated once and kept with the
		// agent's state, so reinstalling still updates the same host.
		if info.MachineID, err = storedMachineID(*stateDir); err != nil {
			return err
		}
	}
	resp, err := newClient().register(ctx, *url, proto.RegisterRequest{
		InstallKey:      *key,
		MachineID:       info.MachineID,
		Hostname:        info.Hostname,
		OS:              info.OS,
		Platform:        info.Platform,
		PlatformVersion: info.PlatformVersion,
		Arch:            info.Arch,
		AgentVersion:    version,
		Tags:            splitTags(*tags),
	})
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	st := state{
		BootstrapURL:    *url,
		IngestURL:       orDefault(resp.Config.IngestURL, *url),
		IntervalSeconds: orDefaultInt(resp.Config.IntervalSeconds, defaultInterval),
		HostID:          resp.HostID,
		HostToken:       resp.HostToken,
	}
	if err := st.save(*stateDir); err != nil {
		return err
	}
	fmt.Printf("Registered %s as host %s\n", info.Hostname, resp.HostID)
	return nil
}

func cmdRun(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "where the agent keeps its state")
	pidFile := fs.String("pidfile", "", "write the process id here (for rc.d scripts that track it)")
	fs.Parse(args)

	if *pidFile != "" {
		if err := os.WriteFile(*pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
			return err
		}
		defer os.Remove(*pidFile)
	}

	st, err := loadState(*stateDir)
	if err != nil {
		return fmt.Errorf("not registered (run `pulsegrid-agent register` first): %w", err)
	}
	col, err := collector.New()
	if err != nil {
		return err
	}
	sp, err := newSpool(*stateDir, spoolMaxBatches)
	if err != nil {
		return err
	}

	col.Watch(st.WatchProcesses, st.WatchServices)
	a := &agent{st: st, stateDir: *stateDir, col: col, spool: sp, client: newClient(), log: log}
	log.Info("agent started", "version", version, "host_id", st.HostID, "ingest_url", st.IngestURL)

	// Under the Windows service manager, it owns start and stop.
	if handled, err := runAsService(a.loop); handled {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	a.loop(ctx)
	return nil
}

type agent struct {
	st       state
	stateDir string
	col      collector.Collector
	spool    *spool
	client   *client
	log      *slog.Logger
	meta     *proto.HostMeta
	metaAt   time.Time
}

func (a *agent) loop(ctx context.Context) {
	a.refreshConfig(ctx)
	ticker := time.NewTicker(a.interval())
	defer ticker.Stop()
	lastRefresh := time.Now()

	for {
		a.tick(ctx)
		if time.Since(lastRefresh) >= configRefreshEvery {
			if a.refreshConfig(ctx) {
				ticker.Reset(a.interval())
			}
			lastRefresh = time.Now()
		}
		select {
		case <-ctx.Done():
			a.log.Info("agent stopping")
			return
		case <-ticker.C:
		}
	}
}

func (a *agent) interval() time.Duration {
	return time.Duration(orDefaultInt(a.st.IntervalSeconds, defaultInterval)) * time.Second
}

func (a *agent) tick(ctx context.Context) {
	tickCtx, cancel := context.WithTimeout(ctx, a.interval())
	defer cancel()

	samples, err := a.col.Collect(tickCtx)
	if err != nil {
		a.log.Warn("collect failed", "err", err)
	}
	if len(samples) > 0 {
		batch := proto.Batch{TimestampMs: time.Now().UnixMilli(), Samples: samples}
		if err := a.spool.add(batch); err != nil {
			a.log.Error("spool write failed", "err", err)
		}
	}
	a.flush(tickCtx)
}

// flush sends spooled batches oldest first until the spool is empty or a push fails.
func (a *agent) flush(ctx context.Context) {
	for ctx.Err() == nil {
		batches, files, err := a.spool.oldest(maxBatchesPerPush)
		if err != nil || len(batches) == 0 {
			return
		}
		err = a.client.push(ctx, a.st.IngestURL, a.st.HostToken, proto.MetricsRequest{
			AgentVersion: version, Batches: batches, Host: a.hostMeta(ctx),
		})
		var se *statusError
		switch {
		case err == nil:
			a.spool.remove(files)
		case errors.As(err, &se) && se.permanent():
			a.log.Error("ingest rejected batches; dropping them", "err", err)
			a.spool.remove(files)
		default:
			// Network trouble, 5xx, or a revoked/suspended credential: keep the
			// data and try again next tick.
			a.log.Warn("push failed; will retry", "err", err)
			return
		}
	}
}

// refreshConfig asks ingest for the current endpoints and interval. If the
// current ingest URL doesn't answer, it falls back to the bootstrap URL, so a
// bad config push can't strand the agent. Reports whether the interval changed.
func (a *agent) refreshConfig(ctx context.Context) bool {
	cfg, err := a.client.config(ctx, a.st.IngestURL, a.st.HostToken)
	if err != nil && a.st.BootstrapURL != a.st.IngestURL {
		cfg, err = a.client.config(ctx, a.st.BootstrapURL, a.st.HostToken)
	}
	if err != nil {
		a.log.Warn("config refresh failed", "err", err)
		return false
	}
	next := a.st
	next.IngestURL = orDefault(cfg.IngestURL, a.st.IngestURL)
	next.IntervalSeconds = orDefaultInt(cfg.IntervalSeconds, a.st.IntervalSeconds)
	next.WatchProcesses, next.WatchServices = cfg.WatchProcesses, cfg.WatchServices
	if sameState(next, a.st) {
		return false
	}
	intervalChanged := next.IntervalSeconds != a.st.IntervalSeconds
	a.col.Watch(next.WatchProcesses, next.WatchServices)
	a.log.Info("config updated", "ingest_url", next.IngestURL, "interval_seconds", next.IntervalSeconds,
		"watch_processes", next.WatchProcesses, "watch_services", next.WatchServices)
	a.st = next
	if err := a.st.save(a.stateDir); err != nil {
		a.log.Error("saving state failed", "err", err)
	}
	return intervalChanged
}

func sameState(a, b state) bool {
	return a.BootstrapURL == b.BootstrapURL && a.IngestURL == b.IngestURL &&
		a.IntervalSeconds == b.IntervalSeconds && a.HostID == b.HostID && a.HostToken == b.HostToken &&
		slices.Equal(a.WatchProcesses, b.WatchProcesses) && slices.Equal(a.WatchServices, b.WatchServices)
}

// hostMeta returns what the agent knows about the machine, re-read every
// metaRefreshEvery.
func (a *agent) hostMeta(ctx context.Context) *proto.HostMeta {
	if a.meta == nil || time.Since(a.metaAt) >= metaRefreshEvery {
		m := collector.Meta(ctx)
		a.meta, a.metaAt = &m, time.Now()
	}
	return a.meta
}

func splitTags(s string) []string {
	var tags []string
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func orDefaultInt(v, fallback int) int {
	if v <= 0 {
		return fallback
	}
	return v
}
