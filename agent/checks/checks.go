// Package checks runs resource and uptime checks: TCP ports, HTTP(S) URLs,
// TLS certificate expiry, DNS records, files and log patterns, and the
// protocol checks in protocols.go. Each check runs on its own interval; the
// agent collects the latest results with each push. Checks come from the
// agent's config, so they are limited to these read-only probes: the only
// command run is the service manager's status query, with a checked name.
package checks

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AlzyWelzy/sentinel/proto"
)

const (
	defaultInterval = 60 * time.Second
	minInterval     = 10 * time.Second
	defaultTimeout  = 10 * time.Second
	maxBodyBytes    = 1 << 20
	maxDetail       = 300
	// A log check reads at most this much new data per run, so a log that
	// grows by gigabytes can't stall the agent.
	maxLogReadBytes = 16 << 20
)

// Runner owns the scheduled checks and their latest results.
type Runner struct {
	mu      sync.Mutex
	checks  map[string]*scheduled
	results map[string]proto.CheckResult
	samples map[string][]proto.Sample
	// HTTP client for http checks; tests replace it.
	client  *http.Client
	version string
}

type scheduled struct {
	check proto.Check
	key   string // identifies the definition, to keep state across identical updates
	next  time.Time
	state checkState
	// A failure not yet delivered: kept, even if later runs pass, until a
	// push has carried it (Ack), so a short failure between pushes (one
	// log line, one refused connection) is never lost.
	held        *proto.CheckResult
	heldSamples []proto.Sample
	// Network checks: diagnose once when a check starts failing, and again
	// every rediagnoseAfter while it keeps failing.
	lastOK      bool
	diagnosedAt time.Time
	shotAt      time.Time
}

// checkState is what a check remembers between runs.
type checkState struct {
	fileHash  string
	logOffset int64
	logInode  uint64
	logPrimed bool
}

func NewRunner(version string) *Runner {
	return &Runner{
		checks:  map[string]*scheduled{},
		results: map[string]proto.CheckResult{},
		samples: map[string][]proto.Sample{},
		version: version,
		client: &http.Client{
			Timeout: defaultTimeout,
			// Report redirects as they are only when asked; by default
			// follow up to 5 like a browser would.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("stopped after 5 redirects")
				}
				return nil
			},
		},
	}
}

func definitionKey(c proto.Check) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%d", c.Type, c.Target, c.IntervalSeconds)
	keys := make([]string, 0, len(c.Params))
	for k := range c.Params {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		fmt.Fprintf(h, "\x00%s=%s", k, c.Params[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Set replaces the check list. Unchanged checks keep their schedule and state
// (a log check keeps its read position), new ones run right away.
func (r *Runner) Set(list []proto.Check) {
	r.mu.Lock()
	defer r.mu.Unlock()
	keep := map[string]bool{}
	for _, c := range list {
		if c.ID == "" {
			continue
		}
		keep[c.ID] = true
		key := definitionKey(c)
		if s, ok := r.checks[c.ID]; ok && s.key == key {
			continue
		}
		r.checks[c.ID] = &scheduled{check: c, key: key}
	}
	for id := range r.checks {
		if !keep[id] {
			delete(r.checks, id)
			delete(r.results, id)
			delete(r.samples, id)
		}
	}
}

func interval(c proto.Check) time.Duration {
	if c.IntervalSeconds <= 0 {
		return defaultInterval
	}
	d := time.Duration(c.IntervalSeconds) * time.Second
	if d < minInterval {
		return minInterval
	}
	return d
}

// RunDue runs every check whose time has come, concurrently, and waits.
func (r *Runner) RunDue(ctx context.Context) {
	now := time.Now()
	r.mu.Lock()
	var due []*scheduled
	for _, s := range r.checks {
		if !now.Before(s.next) {
			s.next = now.Add(interval(s.check))
			due = append(due, s)
		}
	}
	r.mu.Unlock()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, s := range due {
		wg.Add(1)
		sem <- struct{}{}
		go func(s *scheduled) {
			defer wg.Done()
			defer func() { <-sem }()
			res, samples := r.run(ctx, s)
			r.mu.Lock()
			if cur, ok := r.checks[s.check.ID]; ok && cur == s {
				r.results[s.check.ID] = res
				r.samples[s.check.ID] = samples
				if !res.OK {
					s.held, s.heldSamples = &res, samples
				}
			}
			r.mu.Unlock()
		}(s)
	}
	wg.Wait()
}

// Results returns the result of every check to report: a held failure if
// there is one, otherwise the latest result; and their samples.
func (r *Runner) Results() ([]proto.CheckResult, []proto.Sample) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var res []proto.CheckResult
	var samples []proto.Sample
	for id, v := range r.results {
		if s := r.checks[id]; s != nil && s.held != nil {
			res = append(res, *s.held)
			samples = append(samples, s.heldSamples...)
			continue
		}
		res = append(res, v)
		samples = append(samples, r.samples[id]...)
	}
	return res, samples
}

// Ack drops held failures that a push has now delivered. Only those
// reported: a failure that arrived after the push was built stays held.
func (r *Runner) Ack(delivered []proto.CheckResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range delivered {
		if s := r.checks[d.ID]; s != nil && s.held != nil && s.held.TimestampMs == d.TimestampMs {
			s.held, s.heldSamples = nil, nil
		}
	}
}

func (r *Runner) run(ctx context.Context, s *scheduled) (proto.CheckResult, []proto.Sample) {
	c := s.check
	timeout := durationParam(c.Params, "timeout_seconds", defaultTimeout)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if c.Params["public_only"] == "true" {
		ctx = context.WithValue(ctx, publicOnlyKey{}, true)
	}

	start := time.Now()
	out := r.dispatch(ctx, c, s)
	if c.Params["invert"] == "true" {
		// Upside down: up means the thing is unreachable or failing (a
		// port that must stay closed, a page that must stay down).
		if out.ok {
			out = outcome{detail: "expected down, but " + out.detail, latency: out.latency, extra: out.extra}
		} else {
			out = outcome{ok: true, detail: "down, as expected: " + out.detail, latency: out.latency, extra: out.extra}
		}
	}
	latency := time.Since(start)
	if out.latency > 0 {
		latency = out.latency
	}
	res := proto.CheckResult{
		ID:          c.ID,
		OK:          out.ok,
		Detail:      truncate(out.detail, maxDetail),
		LatencyMs:   float64(latency.Microseconds()) / 1000,
		TimestampMs: time.Now().UnixMilli(),
	}
	if !out.ok && len(out.screenshot) > 0 && (s.lastOK || time.Since(s.shotAt) > rediagnoseAfter) {
		res.Screenshot = out.screenshot
		s.shotAt = time.Now()
	}
	if !out.ok && c.Type != "browser" && (s.lastOK || time.Since(s.diagnosedAt) > rediagnoseAfter) {
		if d := diagnose(context.WithoutCancel(ctx), c, c.Params["public_only"] == "true"); d != nil {
			res.Diagnosis = d
			s.diagnosedAt = time.Now()
		}
	}
	s.lastOK = out.ok
	samples := []proto.Sample{
		sample("sentinel_check_up", boolValue(out.ok), c.ID),
	}
	if c.Type != "file" && c.Type != "log" && c.Type != "docker" && c.Type != "service" {
		samples = append(samples, sample("sentinel_check_latency_seconds", latency.Seconds(), c.ID))
	}
	for name, v := range out.extra {
		samples = append(samples, sample(name, v, c.ID))
	}
	return res, samples
}

type outcome struct {
	ok         bool
	detail     string
	latency    time.Duration
	extra      map[string]float64
	screenshot []byte // browser checks: the page when it failed (JPEG)
}

func sample(name string, v float64, checkID string) proto.Sample {
	return proto.Sample{Name: name, Value: v, Labels: map[string]string{"check_id": checkID}}
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func checkTCP(ctx context.Context, target string) outcome {
	if _, _, err := net.SplitHostPort(target); err != nil {
		return outcome{detail: "target must be host:port"}
	}
	d := dialer(ctx)
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return outcome{detail: cleanErr(err)}
	}
	conn.Close()
	return outcome{ok: true, detail: "port open", latency: time.Since(start)}
}

// checkReachable is "is this host up": raw ICMP needs privileges the agent
// doesn't have, so try the usual service ports and count a refusal as up
// (the host answered).
func checkReachable(ctx context.Context, host string) outcome {
	d := dialer(ctx)
	var lastErr error
	for _, port := range []string{"443", "80", "22"} {
		start := time.Now()
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err == nil {
			conn.Close()
			return outcome{ok: true, detail: "reachable on port " + port, latency: time.Since(start)}
		}
		if strings.Contains(err.Error(), "refused") {
			return outcome{ok: true, detail: "host answered (port " + port + " closed)", latency: time.Since(start)}
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return outcome{detail: "unreachable: " + cleanErr(lastErr)}
}

func (r *Runner) checkHTTP(ctx context.Context, c proto.Check) outcome {
	method := strings.ToUpper(c.Params["method"])
	if method == "" {
		method = http.MethodGet
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
	default:
		return outcome{detail: "method must be GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS"}
	}
	var body io.Reader
	if c.Params["body"] != "" && method != http.MethodGet && method != http.MethodHead {
		body = strings.NewReader(c.Params["body"])
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Target, body)
	if err != nil {
		return outcome{detail: "invalid URL"}
	}
	if body != nil {
		ct := map[string]string{"json": "application/json", "form": "application/x-www-form-urlencoded", "xml": "application/xml"}[c.Params["body_encoding"]]
		req.Header.Set("Content-Type", orDefault(ct, "application/json"))
	}
	req.Header.Set("User-Agent", "Sentinel-Monitor/"+r.version)
	if h := c.Params["headers"]; h != "" {
		var hs map[string]string
		if err := json.Unmarshal([]byte(h), &hs); err != nil {
			return outcome{detail: "headers must be a JSON object of strings"}
		}
		for k, v := range hs {
			req.Header.Set(k, v)
		}
	}
	client, err := r.httpClient(ctx, c)
	if err != nil {
		return outcome{detail: err.Error()}
	}
	switch {
	case c.Params["oauth_token_url"] != "":
		tok, err := oauthToken(ctx, client, c.Params)
		if err != nil {
			return outcome{detail: "OAuth " + err.Error()}
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	case c.Params["bearer_token"] != "":
		req.Header.Set("Authorization", "Bearer "+c.Params["bearer_token"])
	case c.Params["basic_user"] != "":
		req.SetBasicAuth(c.Params["basic_user"], c.Params["basic_password"])
	}
	if c.Params["cache_bust"] == "true" {
		q := req.URL.Query()
		q.Set("_sentinel", strconv.FormatInt(time.Now().UnixNano(), 36))
		req.URL.RawQuery = q.Encode()
	}
	if c.Params["follow_redirects"] == "false" {
		cl := *client
		cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client = &cl
	} else if max := intParam(c.Params, "max_redirects", 0); max > 0 {
		cl := *client
		cl.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
			if len(via) > max {
				return fmt.Errorf("more than %d redirects", max)
			}
			return nil
		}
		client = &cl
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return outcome{detail: cleanErr(err)}
	}
	defer resp.Body.Close()
	latency := time.Since(start)
	extra := map[string]float64{"sentinel_check_http_status": float64(resp.StatusCode)}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		extra["sentinel_check_tls_expiry_seconds"] = time.Until(resp.TLS.PeerCertificates[0].NotAfter).Seconds()
	}
	lo, hi := statusRange(c.Params["expect_status"])
	if resp.StatusCode < lo || resp.StatusCode > hi {
		return outcome{detail: fmt.Sprintf("HTTP %d (expected %d-%d)", resp.StatusCode, lo, hi), latency: latency, extra: extra}
	}
	var page []byte
	if c.Params["keyword"] != "" || c.Params["json_path"] != "" {
		page, _ = io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	}
	if kw := c.Params["keyword"]; kw != "" {
		found := strings.Contains(string(page), kw)
		if c.Params["keyword_case_insensitive"] == "true" {
			found = strings.Contains(strings.ToLower(string(page)), strings.ToLower(kw))
		}
		if c.Params["keyword_absent"] == "true" {
			if found {
				return outcome{detail: fmt.Sprintf("HTTP %d, but the page contains %q", resp.StatusCode, kw), latency: latency, extra: extra}
			}
		} else if !found {
			return outcome{detail: fmt.Sprintf("HTTP %d, but %q isn't on the page", resp.StatusCode, kw), latency: latency, extra: extra}
		}
	}
	if path := c.Params["json_path"]; path != "" {
		var doc any
		if err := json.Unmarshal(page, &doc); err != nil {
			return outcome{detail: fmt.Sprintf("HTTP %d, but the answer isn't JSON", resp.StatusCode), latency: latency, extra: extra}
		}
		got, err := jsonPath(doc, path)
		if err != nil {
			return outcome{detail: fmt.Sprintf("HTTP %d, but %s", resp.StatusCode, err), latency: latency, extra: extra}
		}
		if ok, why := compare(got, orDefault(c.Params["json_op"], "=="), c.Params["json_expect"]); !ok {
			return outcome{detail: fmt.Sprintf("%s is %s: %s", path, truncate(got, 80), why), latency: latency, extra: extra}
		}
	}
	if days := intParam(c.Params, "tls_expiry_days", 0); days > 0 {
		if left, ok := extra["sentinel_check_tls_expiry_seconds"]; ok && left < float64(days)*86400 {
			return outcome{detail: fmt.Sprintf("certificate expires in %.0f days", left/86400), latency: latency, extra: extra}
		}
	}
	return outcome{ok: true, detail: fmt.Sprintf("HTTP %d", resp.StatusCode), latency: latency, extra: extra}
}

func statusRange(s string) (int, int) {
	if s == "" {
		return 200, 399
	}
	if lo, hi, ok := strings.Cut(s, "-"); ok {
		l, err1 := strconv.Atoi(strings.TrimSpace(lo))
		h, err2 := strconv.Atoi(strings.TrimSpace(hi))
		if err1 == nil && err2 == nil {
			return l, h
		}
	}
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return v, v
	}
	return 200, 399
}

func checkTLS(ctx context.Context, c proto.Check) outcome {
	host, _, err := net.SplitHostPort(c.Target)
	if err != nil {
		return outcome{detail: "target must be host:port"}
	}
	d := tls.Dialer{NetDialer: dialer(ctx), Config: &tls.Config{ServerName: host}}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", c.Target)
	if err != nil {
		return outcome{detail: cleanErr(err)}
	}
	defer conn.Close()
	latency := time.Since(start)
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return outcome{detail: "no certificate", latency: latency}
	}
	left := time.Until(certs[0].NotAfter)
	extra := map[string]float64{"sentinel_check_tls_expiry_seconds": left.Seconds()}
	days := intParam(c.Params, "tls_expiry_days", 14)
	detail := fmt.Sprintf("certificate valid for %.0f more days (%s)", left.Hours()/24, certs[0].Subject.CommonName)
	if left < time.Duration(days)*24*time.Hour {
		return outcome{detail: fmt.Sprintf("certificate expires in %.0f days", left.Hours()/24), latency: latency, extra: extra}
	}
	return outcome{ok: true, detail: detail, latency: latency, extra: extra}
}

func checkDNS(ctx context.Context, c proto.Check) outcome {
	var res net.Resolver
	if srv := c.Params["server"]; srv != "" {
		if _, _, err := net.SplitHostPort(srv); err != nil {
			srv = net.JoinHostPort(srv, "53")
		}
		guarded := dialer(ctx)
		res = net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return guarded.DialContext(ctx, network, srv)
		}}
	}
	var values []string
	var err error
	switch strings.ToUpper(orDefault(c.Params["record_type"], "A")) {
	case "A", "AAAA":
		var ips []net.IPAddr
		ips, err = res.LookupIPAddr(ctx, c.Target)
		want6 := strings.EqualFold(c.Params["record_type"], "AAAA")
		for _, ip := range ips {
			if (ip.IP.To4() == nil) == want6 {
				values = append(values, ip.IP.String())
			}
		}
	case "CNAME":
		var v string
		v, err = res.LookupCNAME(ctx, c.Target)
		values = []string{strings.TrimSuffix(v, ".")}
	case "MX":
		var mx []*net.MX
		mx, err = res.LookupMX(ctx, c.Target)
		for _, m := range mx {
			values = append(values, strings.TrimSuffix(m.Host, "."))
		}
	case "TXT":
		values, err = res.LookupTXT(ctx, c.Target)
	case "NS":
		var ns []*net.NS
		ns, err = res.LookupNS(ctx, c.Target)
		for _, n := range ns {
			values = append(values, strings.TrimSuffix(n.Host, "."))
		}
	default:
		return outcome{detail: "record_type must be A, AAAA, CNAME, MX, NS or TXT"}
	}
	if err != nil {
		return outcome{detail: cleanErr(err)}
	}
	if len(values) == 0 {
		return outcome{detail: "no records"}
	}
	got := strings.Join(values, ", ")
	if want := c.Params["expect"]; want != "" {
		for _, v := range values {
			if strings.EqualFold(v, want) {
				return outcome{ok: true, detail: got}
			}
		}
		return outcome{detail: fmt.Sprintf("got %s, expected %s", got, want)}
	}
	return outcome{ok: true, detail: got}
}

func checkFile(c proto.Check, st *checkState) outcome {
	fi, err := os.Stat(c.Target)
	exists := err == nil
	extra := map[string]float64{"sentinel_file_exists": boolValue(exists)}
	if exists {
		extra["sentinel_file_size_bytes"] = float64(fi.Size())
		extra["sentinel_file_age_seconds"] = time.Since(fi.ModTime()).Seconds()
	}
	mode := orDefault(c.Params["mode"], "exists")
	switch mode {
	case "exists":
		if !exists {
			return outcome{detail: "missing: " + cleanErr(err), extra: extra}
		}
		return outcome{ok: true, detail: "present", extra: extra}
	case "absent":
		if exists {
			return outcome{detail: "file exists but shouldn't", extra: extra}
		}
		return outcome{ok: true, detail: "absent", extra: extra}
	case "max_age_seconds":
		limit := intParam(c.Params, "value", 86400)
		if !exists {
			return outcome{detail: "missing", extra: extra}
		}
		age := time.Since(fi.ModTime())
		if age > time.Duration(limit)*time.Second {
			return outcome{detail: fmt.Sprintf("last modified %s ago (limit %s)", age.Round(time.Second), time.Duration(limit)*time.Second), extra: extra}
		}
		return outcome{ok: true, detail: fmt.Sprintf("modified %s ago", age.Round(time.Second)), extra: extra}
	case "max_size_bytes":
		limit := int64(intParam(c.Params, "value", 1<<30))
		if !exists {
			return outcome{detail: "missing", extra: extra}
		}
		if fi.Size() > limit {
			return outcome{detail: fmt.Sprintf("%d bytes (limit %d)", fi.Size(), limit), extra: extra}
		}
		return outcome{ok: true, detail: fmt.Sprintf("%d bytes", fi.Size()), extra: extra}
	case "changed":
		// Fails on the run that sees a change, then recovers on the next
		// one: an alert per change. Directories hash their listing.
		if !exists {
			return outcome{detail: "missing", extra: extra}
		}
		sum, err := fingerprint(c.Target, fi)
		if err != nil {
			return outcome{detail: cleanErr(err), extra: extra}
		}
		prev := st.fileHash
		st.fileHash = sum
		if prev != "" && prev != sum {
			return outcome{detail: "changed", extra: extra}
		}
		return outcome{ok: true, detail: "unchanged", extra: extra}
	}
	return outcome{detail: "unknown file mode " + mode}
}

func fingerprint(path string, fi os.FileInfo) (string, error) {
	h := sha256.New()
	if fi.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return "", err
		}
		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				continue
			}
			fmt.Fprintf(h, "%s\x00%d\x00%d\n", e.Name(), info.Size(), info.ModTime().UnixNano())
		}
		return hex.EncodeToString(h.Sum(nil)), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(h, io.LimitReader(f, 256<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// checkLog reads what was appended since the last run and counts lines
// matching the pattern. The first run only notes the end of the file, so
// installing a check doesn't alert on old lines. A rotated or truncated file
// is read from the start.
func checkLog(c proto.Check, st *checkState) outcome {
	pattern := c.Params["pattern"]
	if pattern == "" {
		return outcome{detail: "pattern is required"}
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return outcome{detail: "invalid pattern: " + err.Error()}
	}
	threshold := intParam(c.Params, "threshold", 1)
	f, err := os.Open(c.Target)
	if err != nil {
		return outcome{detail: readErr(c.Target, err)}
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return outcome{detail: cleanErr(err)}
	}
	inode := fileID(fi)
	if !st.logPrimed {
		st.logPrimed, st.logOffset, st.logInode = true, fi.Size(), inode
		return outcome{ok: true, detail: "watching for new lines", extra: map[string]float64{"sentinel_log_matches": 0}}
	}
	if inode != st.logInode || fi.Size() < st.logOffset {
		st.logOffset, st.logInode = 0, inode
	}
	if _, err := f.Seek(st.logOffset, io.SeekStart); err != nil {
		return outcome{detail: cleanErr(err)}
	}
	reader := bufio.NewReaderSize(io.LimitReader(f, maxLogReadBytes), 64<<10)
	matches := 0
	var last string
	var read int64
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 && !strings.HasSuffix(line, "\n") && err == io.EOF {
			// A partial last line: leave it for the next run.
			break
		}
		read += int64(len(line))
		if re.MatchString(line) {
			matches++
			last = strings.TrimSpace(line)
		}
		if err != nil {
			break
		}
	}
	st.logOffset += read
	extra := map[string]float64{"sentinel_log_matches": float64(matches)}
	if matches >= threshold {
		return outcome{detail: fmt.Sprintf("%d matching lines; last: %s", matches, last), extra: extra}
	}
	return outcome{ok: true, detail: fmt.Sprintf("%d matching lines", matches), extra: extra}
}

func durationParam(p map[string]string, key string, fallback time.Duration) time.Duration {
	if v := intParam(p, key, 0); v > 0 {
		if v > 60 {
			v = 60
		}
		return time.Duration(v) * time.Second
	}
	return fallback
}

func intParam(p map[string]string, key string, fallback int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(p[key])); err == nil {
		return v
	}
	return fallback
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// readErr explains the usual reason a log can't be read: the agent runs as
// its own unprivileged user.
func readErr(path string, err error) string {
	if errors.Is(err, os.ErrPermission) {
		return "the agent can't read " + path + ": add its user to the file's group " +
			"(on Debian/Ubuntu: sudo usermod -aG adm sentinel && sudo systemctl restart sentinel-agent)"
	}
	return cleanErr(err)
}

// cleanErr keeps the useful tail of Go's wrapped network errors.
func cleanErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i > 0 && strings.Count(s, ": ") > 1 {
		return s[i+2:]
	}
	return s
}

func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

// jsonPath reads a value with a dotted path: status, data.items[0].state,
// $.a.b (the leading $ is optional). Objects and arrays come back as JSON.
func jsonPath(doc any, path string) (string, error) {
	p := strings.TrimPrefix(strings.TrimPrefix(path, "$"), ".")
	cur := doc
	for p != "" {
		var key string
		if strings.HasPrefix(p, "[") {
			end := strings.Index(p, "]")
			if end < 0 {
				return "", fmt.Errorf("bad path %q", path)
			}
			idx, err := strconv.Atoi(p[1:end])
			arr, ok := cur.([]any)
			if err != nil || !ok {
				return "", fmt.Errorf("%s isn't in the answer", path)
			}
			if idx < 0 {
				idx += len(arr)
			}
			if idx < 0 || idx >= len(arr) {
				return "", fmt.Errorf("%s isn't in the answer", path)
			}
			cur, p = arr[idx], strings.TrimPrefix(p[end+1:], ".")
			continue
		}
		i := strings.IndexAny(p, ".[")
		if i < 0 {
			key, p = p, ""
		} else {
			key, p = p[:i], strings.TrimPrefix(p[i:], ".")
		}
		obj, ok := cur.(map[string]any)
		if !ok {
			return "", fmt.Errorf("%s isn't in the answer", path)
		}
		if cur, ok = obj[key]; !ok {
			return "", fmt.Errorf("%s isn't in the answer", path)
		}
	}
	switch v := cur.(type) {
	case string:
		return v, nil
	case nil:
		return "null", nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	case bool:
		return strconv.FormatBool(v), nil
	}
	b, _ := json.Marshal(cur)
	return string(b), nil
}

// dispatch runs one check. A check that panics (a driver bug, a malformed
// answer nobody anticipated) fails that check, not the agent.
func (r *Runner) dispatch(ctx context.Context, c proto.Check, s *scheduled) (out outcome) {
	defer func() {
		if p := recover(); p != nil {
			out = outcome{detail: fmt.Sprintf("the check crashed: %v", p)}
		}
	}()
	switch c.Type {
	case "tcp":
		return checkTCP(ctx, c.Target)
	case "ping":
		return checkReachable(ctx, c.Target)
	case "http":
		return r.checkHTTP(ctx, c)
	case "browser":
		return r.checkBrowser(ctx, c)
	case "tls":
		return checkTLS(ctx, c)
	case "dns":
		return checkDNS(ctx, c)
	case "file":
		return checkFile(c, &s.state)
	case "log":
		return checkLog(c, &s.state)
	case "websocket":
		return checkWebSocket(ctx, c)
	case "smtp":
		return checkSMTP(ctx, c)
	case "ntp":
		return checkNTP(ctx, c)
	case "redis":
		return checkRedis(ctx, c)
	case "postgres":
		return checkPostgres(ctx, c)
	case "mysql":
		return checkMySQL(ctx, c)
	case "mongodb":
		return checkMongo(ctx, c)
	case "kafka":
		return checkKafka(ctx, c)
	case "mqtt":
		return checkMQTT(ctx, c)
	case "grpc":
		return checkGRPC(ctx, c)
	case "sip":
		return checkSIP(ctx, c)
	case "radius":
		return checkRADIUS(ctx, c)
	case "game":
		return checkGame(ctx, c)
	case "snmp":
		return checkSNMP(ctx, c)
	case "docker":
		return checkDocker(ctx, c)
	case "service":
		return checkService(ctx, c)
	default:
		return outcome{detail: "unknown check type " + c.Type}
	}
}
