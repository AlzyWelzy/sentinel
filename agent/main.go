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
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AlzyWelzy/pulsegrid-beyond/agent/apm"
	"github.com/AlzyWelzy/pulsegrid-beyond/agent/checks"
	"github.com/AlzyWelzy/pulsegrid-beyond/agent/collector"
	"github.com/AlzyWelzy/pulsegrid-beyond/agent/logs"
	"github.com/AlzyWelzy/pulsegrid-beyond/agent/plugins"
	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
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
	// Checks are scheduled on their own intervals; this is how often the
	// agent looks for due ones.
	checkPollEvery = 5 * time.Second
	// Plugin files are re-read this often, so a new one is picked up
	// without restarting the agent.
	pluginReloadEvery     = time.Minute
	logShipEvery          = 10 * time.Second
	maxLogLinesPerPush    = 2000
	defaultInventoryEvery = 6 * time.Hour
	maxDoneActions        = 100
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
	case "allow-action":
		err = cmdAllowAction(os.Args[2:])
	case "enable-hardware":
		err = cmdEnableHardware(os.Args[2:])
	case "hardware-cache":
		err = cmdHardwareCache(os.Args[2:])
	case "autoconfig":
		err = cmdAutoconfig(os.Args[2:])
	case "plugins":
		err = cmdPlugins(os.Args[2:])
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
	fmt.Fprintln(os.Stderr, "       pulsegrid-agent allow-action NAME [--remove] -- /absolute/command args")
	fmt.Fprintln(os.Stderr, "       pulsegrid-agent plugins [--config-dir DIR]   (test the plugin files)")
	fmt.Fprintln(os.Stderr, "       pulsegrid-agent autoconfig [--no-logs] [--off]   (detect services and write their config; as root)")
	fmt.Fprintln(os.Stderr, "       pulsegrid-agent enable-hardware [--remove]   (disk SMART and IPMI sensors; as root)")
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
	configDir := fs.String("config-dir", defaultConfigDir(), "plugin and action files")
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
	runner := checks.NewRunner(version)
	runner.Set(st.Checks)
	a := &agent{
		st: st, stateDir: *stateDir, configDir: *configDir, col: col, spool: sp,
		client: newClient(), log: log, checks: runner,
	}
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

	configDir        string
	checks           *checks.Runner
	plugins          []plugins.Config
	pluginErr        []error
	pluginsAt        time.Time
	lastPluginStatus []proto.PluginStatus
	logStatus        *proto.LogsStatus
	inventoryDue     bool // under mu
	inventoryAt      time.Time
	// Waiting to go out with the next successful push.
	mu            sync.Mutex
	actionResults []proto.ActionResult
	inventory     *proto.Inventory
	running       map[string]bool
	doneActions   []string
	refreshNow    chan struct{}
}

// saveState writes the state, with the done-action list taken under the lock.
func (a *agent) saveState() {
	a.mu.Lock()
	st := a.st
	st.DoneActions = slices.Clone(a.doneActions)
	a.mu.Unlock()
	if err := st.save(a.stateDir); err != nil {
		a.log.Error("saving state failed", "err", err)
	}
}

func (a *agent) loop(ctx context.Context) {
	a.refreshNow = make(chan struct{}, 1)
	a.running = map[string]bool{}
	a.doneActions = slices.Clone(a.st.DoneActions)
	a.refreshConfig(ctx)
	go a.checkLoop(ctx)
	go a.logLoop(ctx)
	go a.apmLoop(ctx)
	ticker := time.NewTicker(a.interval())
	defer ticker.Stop()
	lastRefresh := time.Now()

	for {
		a.tick(ctx)
		refresh := time.Since(lastRefresh) >= configRefreshEvery
		select {
		case <-a.refreshNow:
			refresh = true
		default:
		}
		if refresh {
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
		case <-a.refreshNow:
			// A push said the config changed: fetch it now, then carry on.
			if a.refreshConfig(ctx) {
				ticker.Reset(a.interval())
			}
			lastRefresh = time.Now()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}
}

// checkLoop runs due checks between ticks; results go out with the next push.
func (a *agent) checkLoop(ctx context.Context) {
	t := time.NewTicker(checkPollEvery)
	defer t.Stop()
	for {
		a.checks.RunDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// logLoop ships new lines from the sources in logs.conf. Ingest answering
// 404 means log search isn't enabled there: try again much later.
func (a *agent) logLoop(ctx context.Context) {
	shipper := logs.NewShipper(a.stateDir)
	var cfg logs.Config
	var on bool
	var loadedAt time.Time
	wait := logShipEvery
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = logShipEvery
		if loadedAt.IsZero() || time.Since(loadedAt) >= pluginReloadEvery {
			var err error
			cfg, on, err = logs.LoadConfig(a.configDir)
			loadedAt = time.Now()
			if err != nil {
				a.log.Warn("logs.conf unusable", "err", err)
				a.setLogStatus(&proto.LogsStatus{Problems: []string{err.Error()}})
				continue
			}
			if !on {
				a.setLogStatus(nil)
				continue
			}
		}
		if !on {
			continue
		}
		entries, problems := shipper.Collect(cfg, maxLogLinesPerPush)
		a.setLogStatus(&proto.LogsStatus{Files: cfg.Files, Journal: cfg.Journal, EventLog: cfg.EventLog, Problems: problems})
		if len(entries) == 0 {
			shipper.Commit()
			continue
		}
		pushCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, err := a.client.logs(pushCtx, a.st.IngestURL, a.st.HostToken, proto.LogsRequest{Entries: entries})
		cancel()
		var se *statusError
		switch {
		case err == nil:
			shipper.Commit()
			if len(entries) == maxLogLinesPerPush {
				wait = time.Second // more waiting: catch up
			}
		case errors.As(err, &se) && se.Code == http.StatusNotFound:
			a.log.Info("log search isn't enabled on this Pulsegrid; will check again later")
			wait = 10 * time.Minute
		case errors.As(err, &se) && se.permanent():
			a.log.Warn("ingest rejected log lines; skipping them", "err", err)
			shipper.Commit()
		default:
			a.log.Warn("log push failed; will retry", "err", err)
		}
	}
}

// apmLoop runs the local OTLP receiver while apm.conf asks for it,
// restarting it when the file changes.
func (a *agent) apmLoop(ctx context.Context) {
	var running context.CancelFunc
	var current apm.Config
	failed := make(chan struct{}, 1) // the receiver exited with an error: retry
	stop := func() {
		if running != nil {
			running()
			running = nil
		}
	}
	defer stop()
	forward := func(fctx context.Context, contentType string, body []byte) (bool, error) {
		pctx, cancel := context.WithTimeout(fctx, 30*time.Second)
		defer cancel()
		err := a.client.traces(pctx, a.st.IngestURL, a.st.HostToken, contentType, body)
		var se *statusError
		if errors.As(err, &se) && (se.permanent() || se.Code == http.StatusNotFound) {
			return false, err
		}
		return err != nil, err
	}
	for {
		select {
		case <-failed:
			stop()
		default:
		}
		cfg, on, err := apm.LoadConfig(a.configDir)
		if err != nil {
			a.log.Warn("apm.conf unusable", "err", err)
		}
		switch {
		case (!on || err != nil) && running != nil:
			stop()
			a.log.Info("APM receiver stopped")
		case on && err == nil && (running == nil || cfg != current):
			stop()
			rctx, cancel := context.WithCancel(ctx)
			running, current = cancel, cfg
			recv := apm.NewReceiver(a.log, forward)
			go func() {
				if err := recv.Run(rctx, cfg); err != nil {
					a.log.Error("APM receiver failed; retrying in a minute", "err", err, "addr", cfg.Listen)
					select {
					case failed <- struct{}{}:
					default:
					}
				}
			}()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(pluginReloadEvery):
		}
	}
}

// setLogStatus records what's shipped; a change sends the inventory again
// soon, so the dashboard shows it without waiting hours.
func (a *agent) setLogStatus(st *proto.LogsStatus) {
	a.mu.Lock()
	changed := !reflect.DeepEqual(a.logStatus, st)
	a.logStatus = st
	if changed {
		a.inventoryDue = true
	}
	a.mu.Unlock()
}

// pluginSamples runs the locally configured plugins, re-reading their files
// every pluginReloadEvery.
func (a *agent) pluginSamples(ctx context.Context) []proto.Sample {
	if a.pluginsAt.IsZero() || time.Since(a.pluginsAt) >= pluginReloadEvery {
		a.plugins, a.pluginErr = plugins.Load(filepath.Join(a.configDir, "plugins.d"))
		for _, err := range a.pluginErr {
			a.log.Warn("plugin file skipped", "err", err)
		}
		a.pluginsAt = time.Now()
	}
	if len(a.plugins) == 0 {
		a.lastPluginStatus = pluginErrStatus(a.pluginErr)
		return nil
	}
	var out []proto.Sample
	status := pluginErrStatus(a.pluginErr)
	for _, r := range plugins.Collect(ctx, a.plugins) {
		out = append(out, r.Samples...)
		status = append(status, r.Status)
	}
	a.lastPluginStatus = status
	return out
}

func pluginErrStatus(errs []error) []proto.PluginStatus {
	var out []proto.PluginStatus
	for _, err := range errs {
		out = append(out, proto.PluginStatus{Name: "config", Type: "invalid", Error: err.Error()})
	}
	return out
}

// startActions runs requested actions not already run, one goroutine each.
func (a *agent) startActions(ctx context.Context, reqs []proto.ActionRequest) {
	for _, req := range reqs {
		a.mu.Lock()
		if a.running[req.ID] || slices.Contains(a.doneActions, req.ID) {
			a.mu.Unlock()
			continue
		}
		a.running[req.ID] = true
		a.mu.Unlock()
		go func(req proto.ActionRequest) {
			a.log.Info("running action", "action", req.Name, "id", req.ID)
			res := runAction(ctx, a.configDir, req)
			a.log.Info("action finished", "action", req.Name, "status", res.Status, "exit_code", res.ExitCode)
			a.mu.Lock()
			delete(a.running, req.ID)
			a.actionResults = append(a.actionResults, res)
			a.doneActions = append(a.doneActions, req.ID)
			if n := len(a.doneActions); n > maxDoneActions {
				a.doneActions = a.doneActions[n-maxDoneActions:]
			}
			a.mu.Unlock()
			a.saveState()
			select {
			case a.refreshNow <- struct{}{}:
			default:
			}
		}(req)
	}
}

// maybeInventory collects the inventory when it's due.
func (a *agent) maybeInventory(ctx context.Context) {
	every := defaultInventoryEvery
	if a.st.InventoryIntervalSeconds > 0 {
		every = time.Duration(a.st.InventoryIntervalSeconds) * time.Second
	}
	a.mu.Lock()
	due := a.inventoryDue
	a.inventoryDue = false
	a.mu.Unlock()
	if !due && !a.inventoryAt.IsZero() && time.Since(a.inventoryAt) < every {
		return
	}
	a.inventoryAt = time.Now()
	go func() {
		inv := collector.Inventory(ctx)
		allowed, err := loadActions(a.configDir)
		if err != nil {
			a.log.Warn("actions file unusable", "err", err)
		}
		inv.AllowedActions = allowedActionNames(allowed)
		a.mu.Lock()
		inv.Plugins = a.lastPluginStatus
		inv.Logs = a.logStatus
		a.inventory = &inv
		a.mu.Unlock()
	}()
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
	samples = append(samples, a.pluginSamples(tickCtx)...)
	_, checkSamples := a.checks.Results()
	samples = append(samples, checkSamples...)
	a.maybeInventory(ctx)
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
	n := maxBatchesPerPush
	for ctx.Err() == nil {
		batches, files, err := a.spool.oldest(n)
		if err != nil || len(batches) == 0 {
			return
		}
		results, _ := a.checks.Results()
		a.mu.Lock()
		actionResults, inventory := a.actionResults, a.inventory
		a.mu.Unlock()
		resp, err := a.client.push(ctx, a.st.IngestURL, a.st.HostToken, proto.MetricsRequest{
			AgentVersion: version, Batches: batches, Host: a.hostMeta(ctx),
			CheckResults: results, ActionResults: actionResults, Inventory: inventory,
		})
		var se *statusError
		switch {
		case err == nil:
			a.spool.remove(files)
			a.checks.Ack(results)
			a.mu.Lock()
			a.actionResults = a.actionResults[len(actionResults):]
			if a.inventory == inventory {
				a.inventory = nil
			}
			a.mu.Unlock()
			if resp.ConfigVersion != "" && resp.ConfigVersion != a.st.ConfigVersion {
				select {
				case a.refreshNow <- struct{}{}:
				default:
				}
			}
		case errors.As(err, &se) && se.Code == http.StatusRequestEntityTooLarge && len(batches) > 1:
			// Too big for one request: send fewer at a time. Only a single
			// batch that's still too big is dropped below.
			n = max(1, len(batches)/2)
			a.log.Warn("push too large; sending fewer batches", "batches", n)
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
	next.Checks = cfg.Checks
	next.ConfigVersion = cfg.Version
	next.InventoryIntervalSeconds = cfg.InventoryIntervalSeconds
	a.startActions(ctx, cfg.Actions)
	if sameState(next, a.st) {
		return false
	}
	a.checks.Set(next.Checks)
	intervalChanged := next.IntervalSeconds != a.st.IntervalSeconds
	a.col.Watch(next.WatchProcesses, next.WatchServices)
	a.log.Info("config updated", "ingest_url", next.IngestURL, "interval_seconds", next.IntervalSeconds,
		"watch_processes", next.WatchProcesses, "watch_services", next.WatchServices)
	a.mu.Lock()
	a.st = next
	a.mu.Unlock()
	a.saveState()
	return intervalChanged
}

func sameState(a, b state) bool {
	return a.BootstrapURL == b.BootstrapURL && a.IngestURL == b.IngestURL &&
		a.IntervalSeconds == b.IntervalSeconds && a.HostID == b.HostID && a.HostToken == b.HostToken &&
		slices.Equal(a.WatchProcesses, b.WatchProcesses) && slices.Equal(a.WatchServices, b.WatchServices) &&
		a.ConfigVersion == b.ConfigVersion && a.InventoryIntervalSeconds == b.InventoryIntervalSeconds &&
		reflect.DeepEqual(a.Checks, b.Checks)
}

// cmdPlugins loads and runs the plugin files once, for an administrator
// setting them up: pulsegrid-agent plugins
func cmdPlugins(args []string) error {
	fs := flag.NewFlagSet("plugins", flag.ExitOnError)
	configDir := fs.String("config-dir", defaultConfigDir(), "agent config directory")
	fs.Parse(args)
	dir := filepath.Join(*configDir, "plugins.d")
	list, errs := plugins.Load(dir)
	for _, err := range errs {
		fmt.Printf("SKIPPED  %v\n", err)
	}
	if len(list) == 0 && len(errs) == 0 {
		fmt.Printf("No plugin files in %s. Supported types: %s\n", dir, strings.Join(plugins.Types(), ", "))
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, r := range plugins.Collect(ctx, list) {
		if r.Status.OK {
			fmt.Printf("OK       %s (%s): %d metrics\n", r.Status.Name, r.Status.Type, len(r.Samples)-1)
		} else {
			fmt.Printf("FAILED   %s (%s): %s\n", r.Status.Name, r.Status.Type, r.Status.Error)
		}
	}
	return nil
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
