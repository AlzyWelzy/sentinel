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
}

func loadConfig() config {
	return config{
		ListenAddr:      env("LISTEN_ADDR", ":8080"),
		DatabaseURL:     env("DATABASE_URL", "postgres://pulsegrid_service:pulsegrid_service@localhost:5432/pulsegrid"),
		RedisURL:        env("REDIS_URL", "redis://localhost:6379/0"),
		VictoriaMetrics: env("VICTORIAMETRICS_URL", "http://localhost:8428"),
		PublicIngestURL: env("PUBLIC_INGEST_URL", "http://localhost:8080"),
		IntervalSeconds: envInt("AGENT_INTERVAL_SECONDS", 30),
		AgentVersion:    os.Getenv("AGENT_VERSION"),
		DownloadURL:     os.Getenv("PUBLIC_DOWNLOAD_URL"),
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
		cfg:   cfg,
		store: &store{pool: pool},
		cache: &cache{rdb: rdb},
		vm:    &victoriaMetrics{baseURL: cfg.VictoriaMetrics, client: &http.Client{Timeout: 15 * time.Second}},
		log:   log,
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
