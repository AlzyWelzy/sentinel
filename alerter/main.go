// Command alerter evaluates alert rules, opens and resolves incidents, and
// delivers notifications from the outbound_messages outbox.
//
// Run several replicas for availability: each partition is guarded by a
// Postgres advisory lock, so only one replica evaluates it at a time and the
// others wait as hot standbys. Raise ALERTER_PARTITIONS (and replicas) to
// spread tenants across workers.
package main

import (
	"context"
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

// Arbitrary namespace for this service's advisory locks.
const advisoryLockBase = 0x50475244 // "PGRD"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, env("DATABASE_URL",
		"postgres://pulsegrid_service:pulsegrid_service@localhost:5432/pulsegrid"))
	if err != nil {
		log.Error("postgres", "err", err)
		os.Exit(1)
	}
	defer pool.Close()
	redisOpts, err := redis.ParseURL(env("REDIS_URL", "redis://localhost:6379/0"))
	if err != nil {
		log.Error("redis url", "err", err)
		os.Exit(1)
	}
	rdb := redis.NewClient(redisOpts)
	defer rdb.Close()

	st := &store{pool: pool}
	ev := &evaluator{
		store:     st,
		vmURL:     env("VICTORIAMETRICS_URL", "http://localhost:8428"),
		http:      &http.Client{Timeout: 15 * time.Second},
		rdb:       rdb,
		log:       log,
		baseURL:   os.Getenv("PUBLIC_DASHBOARD_URL"),
		apiURL:    os.Getenv("PUBLIC_API_URL"),
		ackSecret: os.Getenv("ACK_SIGNING_SECRET"),
	}
	disp := &dispatcher{store: st, log: log, senders: senders()}

	interval := time.Duration(envInt("EVALUATION_INTERVAL_SECONDS", 30)) * time.Second
	partitions := envInt("ALERTER_PARTITIONS", 1)

	go disp.run(ctx)
	for p := 0; p < partitions; p++ {
		go evaluatePartition(ctx, pool, ev, p, partitions, interval, log)
	}
	log.Info("alerter started", "partitions", partitions, "interval", interval.String())
	<-ctx.Done()
	log.Info("alerter stopping")
}

func senders() map[string]sender {
	webhook := newWebhookSender(os.Getenv("WEBHOOK_SIGNING_SECRET"), os.Getenv("ALLOW_PRIVATE_WEBHOOKS") == "true")
	public := &http.Client{Timeout: 15 * time.Second}
	twilio := env("TWILIO_API_URL", "https://api.twilio.com")
	return map[string]sender{
		"email":   emailTransport(),
		"webhook": webhook,
		"sms": &smsSender{
			accountSID: os.Getenv("TWILIO_ACCOUNT_SID"),
			authToken:  os.Getenv("TWILIO_AUTH_TOKEN"),
			from:       os.Getenv("TWILIO_FROM"),
			client:     public,
		},
		"voice": &voiceSender{
			accountSID: os.Getenv("TWILIO_ACCOUNT_SID"),
			authToken:  os.Getenv("TWILIO_AUTH_TOKEN"),
			from:       os.Getenv("TWILIO_FROM"),
			client:     public,
			baseURL:    twilio,
		},
		// Customer-supplied URLs: the webhook client refuses private addresses.
		"slack":     &slackSender{client: webhook.client},
		"teams":     &teamsSender{client: webhook.client},
		"discord":   &discordSender{client: webhook.client},
		"telegram":  &telegramSender{client: public, baseURL: env("TELEGRAM_API_URL", "https://api.telegram.org")},
		"pagerduty": &pagerDutySender{client: public, url: env("PAGERDUTY_EVENTS_URL", "https://events.pagerduty.com/v2/enqueue")},
	}
}

// emailTransport: EMAIL_TRANSPORT=console sends through the console backend
// (its own mail settings); smtp (the default) sends directly, for running
// Pulsegrid standalone.
func emailTransport() sender {
	if os.Getenv("EMAIL_TRANSPORT") == "console" {
		return &consoleMailer{
			url:    os.Getenv("CONSOLE_EMAIL_URL"),
			apiKey: os.Getenv("CONSOLE_INTERNAL_API_KEY"),
			client: &http.Client{Timeout: 30 * time.Second},
		}
	}
	return &emailSender{
		host:     os.Getenv("SMTP_HOST"),
		port:     env("SMTP_PORT", "587"),
		username: os.Getenv("SMTP_USERNAME"),
		password: os.Getenv("SMTP_PASSWORD"),
		from:     env("SMTP_FROM", "Pulsegrid <alerts@pulsegrid.local>"),
		tlsMode:  env("SMTP_TLS", "starttls"),
	}
}

// evaluatePartition holds the partition's advisory lock on a dedicated
// connection for as long as it runs; if this replica dies, the connection
// closes, the lock frees, and a standby picks the partition up.
func evaluatePartition(ctx context.Context, pool *pgxpool.Pool, ev *evaluator, p, n int, interval time.Duration, log *slog.Logger) {
	for ctx.Err() == nil {
		conn, err := pool.Acquire(ctx)
		if err != nil {
			sleep(ctx, 5*time.Second)
			continue
		}
		var got bool
		err = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1, $2)", advisoryLockBase, p).Scan(&got)
		if err != nil || !got {
			conn.Release()
			sleep(ctx, 10*time.Second) // another replica owns it; stand by
			continue
		}
		log.Info("partition acquired", "partition", p)
		ticker := time.NewTicker(interval)
		for ctx.Err() == nil {
			ev.evaluateAll(ctx, p, n)
			if conn.Ping(ctx) != nil {
				break // lost the lock's connection; reacquire
			}
			select {
			case <-ctx.Done():
			case <-ticker.C:
			}
		}
		ticker.Stop()
		conn.Release()
	}
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil && v > 0 {
		return v
	}
	return fallback
}
