package main

// ClickHouse over its HTTP interface: the IPDR evidence store. Every table
// carries tenant_id (first in the sort key, so one organisation's search
// reads only its own parts) and expires, the day a row may be deleted,
// fixed at insert from the organisation's retention.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type clickhouse struct {
	url, user, password, db string
	http                    *http.Client
}

func newClickHouse(rawURL, user, password, db string) *clickhouse {
	if rawURL == "" {
		return nil
	}
	return &clickhouse{url: strings.TrimRight(rawURL, "/"), user: user, password: password, db: db,
		http: &http.Client{Timeout: 60 * time.Second}}
}

func (c *clickhouse) do(ctx context.Context, query string, body io.Reader, withDB bool) error {
	q := url.Values{"query": {query}}
	if withDB {
		q.Set("database", c.db)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/?"+q.Encode(), body)
	if err != nil {
		return err
	}
	if c.user != "" {
		req.SetBasicAuth(c.user, c.password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("clickhouse: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *clickhouse) exec(ctx context.Context, query string) error {
	return c.do(ctx, query, nil, true)
}

// insert writes rows as JSONEachRow.
func (c *clickhouse) insert(ctx context.Context, table string, rows []map[string]any) error {
	if len(rows) == 0 {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return c.do(ctx, "INSERT INTO "+table+" SETTINGS async_insert=0, input_format_skip_unknown_fields=1 FORMAT JSONEachRow", &buf, true)
}

// evidenceSchema is idempotent; ingest applies it at start. The API reads
// these tables; jobs seal and expire them.
func evidenceSchema(db string) []string {
	common := "tenant_id UUID, received_at DateTime64(3, 'UTC'), expires Date"
	tail := func(order string) string {
		return ") ENGINE = MergeTree PARTITION BY toYYYYMM(received_at) ORDER BY (tenant_id, " + order + ", received_at)" +
			" TTL expires DELETE SETTINGS index_granularity = 8192"
	}
	return []string{
		"CREATE DATABASE IF NOT EXISTS " + db,
		`CREATE TABLE IF NOT EXISTS fw_sessions (` + common + `,
			event_time DateTime64(3, 'UTC'), source IPv6, device_id String, devname LowCardinality(String),
			logid LowCardinality(String), subtype LowCardinality(String), action LowCardinality(String),
			policy_id UInt32, proto UInt8, service LowCardinality(String), app String,
			src_ip IPv6, src_port UInt16, src_intf LowCardinality(String), src_mac String,
			dst_ip IPv6, dst_port UInt16, dst_intf LowCardinality(String),
			nat_src_ip IPv6, nat_src_port UInt16, nat_dst_ip IPv6, nat_dst_port UInt16,
			user String, session_id UInt64, duration UInt32, sent_bytes UInt64, rcvd_bytes UInt64,
			raw String CODEC(ZSTD(3)),
			INDEX ix_dst dst_ip TYPE bloom_filter(0.01) GRANULARITY 4,
			INDEX ix_nsrc nat_src_ip TYPE bloom_filter(0.01) GRANULARITY 4,
			INDEX ix_ndst nat_dst_ip TYPE bloom_filter(0.01) GRANULARITY 4,
			INDEX ix_user user TYPE bloom_filter(0.01) GRANULARITY 4` + tail("src_ip"),
		`CREATE TABLE IF NOT EXISTS flows (` + common + `,
			flow_start DateTime64(3, 'UTC'), flow_end DateTime64(3, 'UTC'), exporter IPv6, device_id String,
			flow_type LowCardinality(String), sampling UInt32, proto UInt8,
			src_ip IPv6, dst_ip IPv6, src_port UInt16, dst_port UInt16, in_if UInt32, out_if UInt32,
			bytes UInt64, packets UInt64, tcp_flags UInt8, vlan UInt16, src_mac String, dst_mac String,
			INDEX ix_dst dst_ip TYPE bloom_filter(0.01) GRANULARITY 4` + tail("src_ip"),
		`CREATE TABLE IF NOT EXISTS syslog (` + common + `,
			event_time DateTime64(3, 'UTC'), source IPv6, device_id String, facility Int8, severity Int8,
			hostname LowCardinality(String), program LowCardinality(String), message String CODEC(ZSTD(3)),
			raw String CODEC(ZSTD(3)), ips Array(IPv6), parsed UInt8,
			INDEX ix_ips ips TYPE bloom_filter(0.01) GRANULARITY 4,
			INDEX ix_msg message TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4` + tail("source"),
		`CREATE TABLE IF NOT EXISTS ip_users (` + common + `,
			event_time DateTime64(3, 'UTC'), ip IPv6, user String, source IPv6, device_id String,
			action LowCardinality(String), raw String CODEC(ZSTD(3)),
			INDEX ix_user user TYPE bloom_filter(0.01) GRANULARITY 4` + tail("ip"),
		`CREATE TABLE IF NOT EXISTS mac_table (` + common + `,
			device_id String, port LowCardinality(String), if_index UInt32, vlan UInt16, mac String, ip IPv6,
			source LowCardinality(String),
			INDEX ix_ip ip TYPE bloom_filter(0.01) GRANULARITY 4` + tail("mac"),
	}
}

func (c *clickhouse) migrate(ctx context.Context) error {
	for i, q := range evidenceSchema(c.db) {
		if err := c.do(ctx, q, nil, i > 0); err != nil {
			return err
		}
	}
	return nil
}

// chTime formats a time for DateTime64(3).
func chTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05.000") }
