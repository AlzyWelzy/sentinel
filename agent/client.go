package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/AlzyWelzy/sentinel/proto"
)

type client struct {
	http *http.Client
}

func newClient() *client {
	return &client{http: &http.Client{Timeout: 20 * time.Second}}
}

// statusError carries the HTTP status so the caller can decide whether a
// failed push is worth retrying.
type statusError struct {
	Code int
	Body string
}

func (e *statusError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Code, e.Body) }

// permanent reports whether retrying the same request can never succeed.
func (e *statusError) permanent() bool {
	return e.Code == http.StatusBadRequest || e.Code == http.StatusRequestEntityTooLarge
}

// refused reports whether ingest no longer accepts this server's token: the
// server was removed, or its organisation suspended. Retrying every tick
// can't help until someone acts, so callers back off.
func (e *statusError) refused() bool {
	return e.Code == http.StatusUnauthorized || e.Code == http.StatusForbidden
}

func (c *client) do(ctx context.Context, method, url, token string, in, out any) error {
	var body io.Reader
	var gzipped bool
	if in != nil {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if err := json.NewEncoder(gz).Encode(in); err != nil {
			return err
		}
		if err := gz.Close(); err != nil {
			return err
		}
		body = &buf
		gzipped = true
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "sentinel-agent/"+version)
	if gzipped {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", "gzip")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &statusError{Code: resp.StatusCode, Body: strings.TrimSpace(string(msg))}
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *client) register(ctx context.Context, baseURL string, req proto.RegisterRequest) (proto.RegisterResponse, error) {
	var resp proto.RegisterResponse
	err := c.do(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/v1/register", "", req, &resp)
	return resp, err
}

func (c *client) push(ctx context.Context, baseURL, token string, req proto.MetricsRequest) (proto.MetricsResponse, error) {
	var resp proto.MetricsResponse
	err := c.do(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/v1/metrics", token, req, &resp)
	return resp, err
}

func (c *client) logs(ctx context.Context, baseURL, token string, req proto.LogsRequest) (proto.LogsResponse, error) {
	var resp proto.LogsResponse
	err := c.do(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/v1/logs", token, req, &resp)
	return resp, err
}

// traces forwards an OTLP body as received, gzipped on the way.
func (c *client) traces(ctx context.Context, baseURL, token, contentType string, body []byte) error {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write(body)
	if err := gz.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/v1/traces", &buf)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "sentinel-agent/"+version)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &statusError{Code: resp.StatusCode, Body: strings.TrimSpace(string(msg))}
	}
	return nil
}

func (c *client) config(ctx context.Context, baseURL, token string) (proto.AgentConfig, error) {
	var cfg proto.AgentConfig
	err := c.do(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/v1/agent/config", token, nil, &cfg)
	return cfg, err
}
