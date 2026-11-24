// Command ingest receives agent registrations and metric pushes, and writes
// metrics to VictoriaMetrics under the pushing host's tenant.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type config struct {
	ListenAddr      string
	DatabaseURL     string
	RedisURL        string
	VictoriaMetrics string
	PublicIngestURL string
	IntervalSeconds int
	AgentVersion    string
	DownloadURL     string
	// VictoriaLogs for log search; empty turns it off.
	VictoriaLogsURL   string
	LogLinesPerMinute int
	// Tempo for APM traces; empty turns it off.
	TempoURL       string
	SpansPerMinute int
	// Opens network device credentials for the agents that poll them
	// (the API's CREDENTIALS_KEY).
	CredentialsKey string
	// ClickHouse for IPDR evidence; empty turns /v1/evidence off.
	ClickHouseURL, ClickHouseUser, ClickHousePassword, ClickHouseDB string
	// Ports the evidence collector listens on: syslog UDP, syslog TCP,
	// sFlow, NetFlow, IPFIX.
	EvidencePorts [5]int
}

func loadConfig() config {
	return config{
		ListenAddr:         env("LISTEN_ADDR", ":8080"),
		DatabaseURL:        env("DATABASE_URL", "postgres://sentinel_service:sentinel_service@localhost:5432/sentinel"),
		RedisURL:           env("REDIS_URL", "redis://localhost:6379/0"),
		VictoriaMetrics:    env("VICTORIAMETRICS_URL", "http://localhost:8428"),
		PublicIngestURL:    env("PUBLIC_INGEST_URL", "http://localhost:8080"),
		IntervalSeconds:    envInt("AGENT_INTERVAL_SECONDS", 30),
		AgentVersion:       os.Getenv("AGENT_VERSION"),
		DownloadURL:        os.Getenv("PUBLIC_DOWNLOAD_URL"),
		VictoriaLogsURL:    os.Getenv("VICTORIALOGS_URL"),
		LogLinesPerMinute:  envInt("LOG_LINES_PER_MINUTE", 6000),
		TempoURL:           os.Getenv("TEMPO_URL"),
		SpansPerMinute:     envInt("SPANS_PER_MINUTE", 30000),
		CredentialsKey:     os.Getenv("CREDENTIALS_KEY"),
		ClickHouseURL:      os.Getenv("CLICKHOUSE_URL"),
		ClickHouseUser:     env("CLICKHOUSE_USER", "default"),
		ClickHousePassword: os.Getenv("CLICKHOUSE_PASSWORD"),
		ClickHouseDB:       env("CLICKHOUSE_DB", "sentinel"),
		// Unprivileged by default; `install.sh --evidence` lets the agent
		// bind 514 and 601 too (EVIDENCE_SYSLOG_*_PORT=514/601 then).
		EvidencePorts: [5]int{envInt("EVIDENCE_SYSLOG_UDP_PORT", 1514), envInt("EVIDENCE_SYSLOG_TCP_PORT", 1601),
			envInt("EVIDENCE_SFLOW_PORT", 6343), envInt("EVIDENCE_NETFLOW_PORT", 2055), envInt("EVIDENCE_IPFIX_PORT", 4739)},
	}
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg := loadConfig()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("postgres", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	redisOpts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		log.Error("redis url", "err", err)
		os.Exit(1)
	}
	rdb := redis.NewClient(redisOpts)
	defer rdb.Close()

	srv := &server{
		cfg:     cfg,
		store:   &store{pool: pool, billing: os.Getenv("RAZORPAY_KEY_ID") != ""},
		cache:   &cache{rdb: rdb},
		vm:      &victoriaMetrics{baseURL: cfg.VictoriaMetrics, client: &http.Client{Timeout: 15 * time.Second}},
		log:     log,
		configs: newConfigCache(),
		limits:  newLimits(),
	}
	if cfg.TempoURL != "" {
		srv.tempo = &tempo{baseURL: cfg.TempoURL, client: &http.Client{Timeout: 15 * time.Second}}
	}
	if srv.ch = newClickHouse(cfg.ClickHouseURL, cfg.ClickHouseUser, cfg.ClickHousePassword, cfg.ClickHouseDB); srv.ch != nil {
		go func() {
			// ClickHouse may start after ingest: keep trying.
			for i := 0; ; i++ {
				mctx, cancel := context.WithTimeout(ctx, 30*time.Second)
				err := srv.ch.migrate(mctx)
				cancel()
				if err == nil {
					log.Info("evidence store ready")
					return
				}
				log.Warn("evidence store not ready", "err", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(min(time.Duration(i+1)*5*time.Second, time.Minute)):
				}
			}
		}()
	}
	if cfg.VictoriaLogsURL != "" {
		srv.vlogs = &vlogs{baseURL: cfg.VictoriaLogsURL, client: &http.Client{Timeout: 15 * time.Second}}
	}
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdownCtx)
	}()

	log.Info("ingest listening", "addr", cfg.ListenAddr)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("http server", "err", err)
		os.Exit(1)
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return fallback
}
