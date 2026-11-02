// Package apm receives OpenTelemetry traces from applications on the same
// server (OTLP over HTTP, the standard port 4318) and forwards them to
// Sentinel with the agent's own credentials, so applications need no
// Sentinel key: point them at OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318.
//
// Opt-in on the server, root-owned like plugins:
//
//	# <config dir>/apm.conf
//	listen = 127.0.0.1:4318
//
// The agent doesn't decode traces; ingest does (and stamps the host on
// them). Bodies wait in a bounded queue: when it's full the receiver
// answers 503 and the SDK backs off and retries.
package apm

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AlzyWelzy/pulsegrid-beyond/agent/plugins"
)

const (
	// ConfigFile is the file name in the agent's config directory.
	ConfigFile   = "apm.conf"
	maxBody      = 8 << 20
	maxQueued    = 32 << 20
	forwardEvery = 2 * time.Second
)

// Config is what apm.conf asks for.
type Config struct {
	Listen string
}

// LoadConfig reads apm.conf; a missing file means APM is off.
func LoadConfig(dir string) (Config, bool, error) {
	path := filepath.Join(dir, ConfigFile)
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, false, nil
	}
	if err != nil {
		return Config{}, false, err
	}
	defer f.Close()
	if err := plugins.CheckOwnership(path); err != nil {
		return Config{}, false, err
	}
	c := Config{Listen: "127.0.0.1:4318"}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return Config{}, false, fmt.Errorf("%s line %d: expected key = value", ConfigFile, n)
		}
		switch strings.TrimSpace(k) {
		case "listen":
			c.Listen = strings.TrimSpace(v)
			if _, _, err := net.SplitHostPort(c.Listen); err != nil {
				return Config{}, false, fmt.Errorf("%s line %d: listen must be host:port", ConfigFile, n)
			}
		default:
			return Config{}, false, fmt.Errorf("%s line %d: unknown key %q", ConfigFile, n, strings.TrimSpace(k))
		}
	}
	return c, true, sc.Err()
}

type payload struct {
	contentType string
	body        []byte
}

// Forwarder posts queued trace batches; it reports a permanent rejection
// (bad batch) separately from a retryable failure.
type Forwarder func(ctx context.Context, contentType string, body []byte) (retry bool, err error)

// Receiver is the local OTLP/HTTP endpoint.
type Receiver struct {
	log     *slog.Logger
	forward Forwarder

	mu     sync.Mutex
	queue  []payload
	queued int
	// Counters for the inventory: what came in and what was refused.
	Received, Refused int64
}

// NewReceiver makes a receiver that hands batches to forward.
func NewReceiver(log *slog.Logger, forward Forwarder) *Receiver {
	return &Receiver{log: log, forward: forward}
}

// Run serves cfg.Listen until ctx ends, forwarding in the background.
func (r *Receiver) Run(ctx context.Context, cfg Config) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/traces", r.handleTraces)
	srv := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	go r.forwardLoop(ctx)
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	r.log.Info("APM receiver listening", "addr", cfg.Listen)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (r *Receiver) handleTraces(w http.ResponseWriter, req *http.Request) {
	ct := req.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/x-protobuf") && !strings.HasPrefix(ct, "application/json") {
		http.Error(w, "Content-Type must be application/x-protobuf or application/json", http.StatusUnsupportedMediaType)
		return
	}
	var reader io.Reader = req.Body
	if req.Header.Get("Content-Encoding") == "gzip" {
		// Forwarded as-is would need the header kept; simpler to inflate here.
		gz, err := newGzipReader(req.Body)
		if err != nil {
			http.Error(w, "bad gzip body", http.StatusBadRequest)
			return
		}
		defer gz.Close()
		reader = gz
	}
	body, err := io.ReadAll(io.LimitReader(reader, maxBody+1))
	if err != nil || len(body) > maxBody {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	r.mu.Lock()
	if r.queued+len(body) > maxQueued {
		r.Refused++
		r.mu.Unlock()
		w.Header().Set("Retry-After", "5")
		http.Error(w, "queue full", http.StatusServiceUnavailable)
		return
	}
	r.queue = append(r.queue, payload{contentType: ct, body: body})
	r.queued += len(body)
	r.Received++
	r.mu.Unlock()
	// An empty ExportTraceServiceResponse.
	if strings.HasPrefix(ct, "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
}

func (r *Receiver) forwardLoop(ctx context.Context) {
	t := time.NewTicker(forwardEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for ctx.Err() == nil {
			r.mu.Lock()
			if len(r.queue) == 0 {
				r.mu.Unlock()
				break
			}
			p := r.queue[0]
			r.mu.Unlock()
			retry, err := r.forward(ctx, p.contentType, p.body)
			if err != nil && retry {
				r.log.Warn("trace forward failed; will retry", "err", err)
				break
			}
			if err != nil {
				r.log.Warn("ingest rejected a trace batch; dropping it", "err", err)
			}
			r.mu.Lock()
			r.queue = r.queue[1:]
			r.queued -= len(p.body)
			r.mu.Unlock()
		}
	}
}
