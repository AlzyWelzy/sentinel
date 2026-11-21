package checks

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"

	"github.com/AlzyWelzy/sentinel/proto"
)

// Real-browser checks: a page loaded in headless Chromium, its scripts run,
// then optional steps (click, type, wait for, expect text). Failures carry
// a screenshot. On public probes every connection the browser makes goes
// through a local proxy that applies the same public-address guard as the
// other checks, so a page can't make the probe reach a private network.

const (
	browserTimeout   = 30 * time.Second
	maxBrowserTime   = 90 * time.Second
	maxSteps         = 25
	maxScreenshot    = 256 << 10
	browserViewportW = 1280
	browserViewportH = 800
)

// One browser at a time per agent: Chromium is heavy, and checks are
// spread over the interval anyway.
var browserSlot = make(chan struct{}, 1)

type browserStep struct {
	Action   string `json:"action"` // goto, click, type, wait, expect_text, expect_no_text, sleep
	Selector string `json:"selector,omitempty"`
	Text     string `json:"text,omitempty"`
	URL      string `json:"url,omitempty"`
	Ms       int    `json:"ms,omitempty"`
}

func parseSteps(raw string) ([]browserStep, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var steps []browserStep
	if err := json.Unmarshal([]byte(raw), &steps); err != nil {
		return nil, errors.New("steps must be a JSON list")
	}
	if len(steps) > maxSteps {
		return nil, fmt.Errorf("at most %d steps", maxSteps)
	}
	for i, s := range steps {
		switch s.Action {
		case "click", "wait":
			if s.Selector == "" {
				return nil, fmt.Errorf("step %d (%s) needs a selector", i+1, s.Action)
			}
		case "type":
			if s.Selector == "" {
				return nil, fmt.Errorf("step %d (type) needs a selector", i+1)
			}
		case "expect_text", "expect_no_text":
			if s.Text == "" {
				return nil, fmt.Errorf("step %d (%s) needs text", i+1, s.Action)
			}
		case "goto":
			if !strings.HasPrefix(s.URL, "http://") && !strings.HasPrefix(s.URL, "https://") {
				return nil, fmt.Errorf("step %d (goto) needs an http(s) url", i+1)
			}
		case "sleep":
			if s.Ms <= 0 || s.Ms > 10000 {
				return nil, fmt.Errorf("step %d (sleep) is 1-10000 ms", i+1)
			}
		default:
			return nil, fmt.Errorf("step %d: unknown action %q", i+1, s.Action)
		}
	}
	return steps, nil
}

// findChromium: SENTINEL_CHROME, else the usual names on PATH.
func findChromium() string {
	if p := os.Getenv("SENTINEL_CHROME"); p != "" {
		return p
	}
	for _, name := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome", "headless-shell"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	for _, p := range []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

type pageStats struct {
	mu            sync.Mutex
	requests      int
	failed        int
	firstFailed   string
	consoleErrors int
	firstConsole  string
}

func (s *pageStats) listen(ev any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch e := ev.(type) {
	case *network.EventRequestWillBeSent:
		s.requests++
	case *network.EventLoadingFailed:
		if e.Canceled || e.ErrorText == "net::ERR_ABORTED" {
			return
		}
		s.failed++
		if s.firstFailed == "" {
			s.firstFailed = e.ErrorText
		}
	case *runtime.EventExceptionThrown:
		s.consoleErrors++
		if s.firstConsole == "" && e.ExceptionDetails != nil {
			msg := e.ExceptionDetails.Text
			if e.ExceptionDetails.Exception != nil && e.ExceptionDetails.Exception.Description != "" {
				msg = strings.SplitN(e.ExceptionDetails.Exception.Description, "\n", 2)[0]
			}
			s.firstConsole = msg
		}
	case *runtime.EventConsoleAPICalled:
		if e.Type == runtime.APITypeError {
			s.consoleErrors++
			if s.firstConsole == "" && len(e.Args) > 0 {
				s.firstConsole = strings.Trim(string(e.Args[0].Value), `"`)
			}
		}
	}
}

var errNoChromium = errors.New("no Chromium on this machine: install chromium (or google-chrome), or set a remote browser")

// noSandbox is set once Chromium has failed to start with its sandbox here.
var noSandbox atomic.Bool

// startBrowser launches (or connects to) a browser and opens a tab with
// network and runtime events on.
func startBrowser(ctx context.Context, p map[string]string, proxy string, stats *pageStats, unsandboxed bool) (context.Context, func(), error) {
	var alloc context.Context
	var cancelAlloc context.CancelFunc
	if ws := p["browser_ws"]; ws != "" {
		alloc, cancelAlloc = chromedp.NewRemoteAllocator(ctx, ws)
	} else {
		bin := findChromium()
		if bin == "" {
			return ctx, func() {}, errNoChromium
		}
		opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
		opts = append(opts,
			chromedp.ExecPath(bin),
			chromedp.WindowSize(browserViewportW, browserViewportH),
			chromedp.WSURLReadTimeout(15*time.Second),
			chromedp.Flag("force-webrtc-ip-handling-policy", "disable_non_proxied_udp"),
			chromedp.Flag("webrtc-ip-handling-policy", "disable_non_proxied_udp"),
			chromedp.Flag("disable-features", "WebRtcHideLocalIpsWithMdns,Translate,MediaRouter"),
		)
		if unsandboxed || os.Geteuid() == 0 || os.Getenv("SENTINEL_BROWSER_NO_SANDBOX") == "1" {
			opts = append(opts, chromedp.NoSandbox)
		}
		if p["tls_skip_verify"] == "true" {
			opts = append(opts, chromedp.Flag("ignore-certificate-errors", true))
		}
		if proxy != "" {
			opts = append(opts,
				chromedp.ProxyServer("http://"+proxy),
				// Loopback too: Chromium bypasses the proxy for it by default.
				chromedp.Flag("proxy-bypass-list", "<-loopback>"),
			)
		}
		alloc, cancelAlloc = chromedp.NewExecAllocator(ctx, opts...)
	}
	bctx, cancelBrowser := chromedp.NewContext(alloc)
	closeAll := func() { cancelBrowser(); cancelAlloc() }
	chromedp.ListenTarget(bctx, stats.listen)
	if err := chromedp.Run(bctx, network.Enable(), runtime.Enable()); err != nil {
		closeAll()
		return bctx, func() {}, err
	}
	return bctx, closeAll, nil
}

func (r *Runner) checkBrowser(ctx context.Context, c proto.Check) (out outcome) {
	p := c.Params
	steps, err := parseSteps(p["steps"])
	if err != nil {
		return outcome{detail: err.Error()}
	}
	publicOnly := p["public_only"] == "true"
	timeout := min(durationParam(p, "timeout_seconds", browserTimeout), maxBrowserTime)
	select {
	case browserSlot <- struct{}{}:
		defer func() { <-browserSlot }()
	case <-ctx.Done():
		return outcome{detail: "another browser check was still running"}
	}
	// The run's context has the check timeout; the browser gets its own.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout+10*time.Second)
	defer cancel()

	if p["browser_ws"] != "" && publicOnly {
		return outcome{detail: "a remote browser can't be used from public probes"}
	}
	var proxy string
	if publicOnly && p["browser_ws"] == "" {
		addr, stop, err := startGuardProxy()
		if err != nil {
			return outcome{detail: "couldn't start the probe's browser proxy: " + err.Error()}
		}
		defer stop()
		proxy = addr
	}
	stats := &pageStats{}
	bctx, closeBrowser, err := startBrowser(ctx, p, proxy, stats, noSandbox.Load())
	if err != nil && !errors.Is(err, errNoChromium) && p["browser_ws"] == "" && !noSandbox.Load() {
		// Ubuntu 24.04 (AppArmor) and many containers refuse the user
		// namespaces Chromium's sandbox needs: run without it from now on.
		closeBrowser()
		noSandbox.Store(true)
		bctx, closeBrowser, err = startBrowser(ctx, p, proxy, stats, true)
	}
	defer closeBrowser()
	if errors.Is(err, errNoChromium) {
		return outcome{detail: err.Error()}
	}
	if err != nil {
		return outcome{detail: "the browser didn't start: " + cleanErr(err)}
	}
	if ua := p["user_agent"]; ua != "" {
		_ = chromedp.Run(bctx, emulation.SetUserAgentOverride(ua))
	}
	if h := p["headers"]; h != "" {
		var hs map[string]any
		if json.Unmarshal([]byte(h), &hs) != nil {
			return outcome{detail: "headers must be a JSON object of strings"}
		}
		_ = chromedp.Run(bctx, network.SetExtraHTTPHeaders(network.Headers(hs)))
	}

	runCtx, cancelRun := context.WithTimeout(bctx, timeout)
	defer cancelRun()
	shot := func(detail string) outcome {
		o := outcome{detail: detail}
		var buf []byte
		sctx, cancel := context.WithTimeout(bctx, 8*time.Second)
		defer cancel()
		if chromedp.Run(sctx, chromedp.ActionFunc(func(ctx context.Context) error {
			b, err := page.CaptureScreenshot().WithFormat(page.CaptureScreenshotFormatJpeg).WithQuality(55).Do(ctx)
			buf = b
			return err
		})) == nil && len(buf) <= maxScreenshot {
			o.screenshot = buf
		}
		return o
	}

	start := time.Now()
	resp, err := chromedp.RunResponse(runCtx, chromedp.Navigate(c.Target))
	if err != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return shot(fmt.Sprintf("the page didn't load within %s", timeout))
		}
		return shot("loading the page: " + browserErr(err))
	}
	loaded := time.Since(start)
	extra := map[string]float64{}
	if resp != nil {
		extra["sentinel_check_http_status"] = float64(resp.Status)
		lo, hi := statusRange(p["expect_status"])
		if int(resp.Status) < lo || int(resp.Status) > hi {
			o := shot(fmt.Sprintf("HTTP %d (expected %d-%d)", resp.Status, lo, hi))
			o.extra = extra
			return o
		}
	}
	var nav struct {
		DOM      float64 `json:"dom"`
		Load     float64 `json:"load"`
		Transfer float64 `json:"transfer"`
	}
	_ = chromedp.Run(runCtx, chromedp.Evaluate(`(() => { const n = performance.getEntriesByType("navigation")[0] || {};
		return {dom: n.domContentLoadedEventEnd || 0, load: n.loadEventEnd || 0, transfer: n.transferSize || 0}; })()`, &nav))
	if nav.DOM > 0 {
		extra["sentinel_check_browser_dom_seconds"] = nav.DOM / 1000
	}
	if nav.Load > 0 {
		extra["sentinel_check_browser_load_seconds"] = nav.Load / 1000
		loaded = time.Duration(nav.Load * float64(time.Millisecond))
	}

	for i, s := range steps {
		if err := runStep(runCtx, s, p); err != nil {
			o := shot(fmt.Sprintf("step %d (%s): %s", i+1, describeStep(s), err))
			o.extra = extra
			return o
		}
	}
	if kw := p["keyword"]; kw != "" {
		var text string
		_ = chromedp.Run(runCtx, chromedp.Evaluate(`document.body ? document.body.innerText : ""`, &text))
		if found := strings.Contains(text, kw); found == (p["keyword_absent"] == "true") {
			msg := fmt.Sprintf("%q isn't on the page", kw)
			if found {
				msg = fmt.Sprintf("the page contains %q", kw)
			}
			o := shot(msg)
			o.extra = extra
			return o
		}
	}

	stats.mu.Lock()
	requests, failed, firstFailed, consoleErrors, firstConsole := stats.requests, stats.failed, stats.firstFailed, stats.consoleErrors, stats.firstConsole
	stats.mu.Unlock()
	extra["sentinel_check_browser_requests"] = float64(requests)
	extra["sentinel_check_browser_failed_requests"] = float64(failed)
	extra["sentinel_check_browser_console_errors"] = float64(consoleErrors)
	if max := intParam(p, "max_console_errors", -1); max >= 0 && consoleErrors > max {
		o := shot(fmt.Sprintf("%d script errors (at most %d): %s", consoleErrors, max, truncate(firstConsole, 160)))
		o.extra = extra
		return o
	}
	if max := intParam(p, "max_failed_requests", -1); max >= 0 && failed > max {
		o := shot(fmt.Sprintf("%d requests failed (at most %d): %s", failed, max, firstFailed))
		o.extra = extra
		return o
	}
	if max := intParam(p, "max_load_ms", 0); max > 0 && loaded > time.Duration(max)*time.Millisecond {
		o := shot(fmt.Sprintf("loaded in %d ms (at most %d)", loaded.Milliseconds(), max))
		o.extra = extra
		return o
	}
	detail := fmt.Sprintf("loaded in %d ms, %d requests", loaded.Milliseconds(), requests)
	if len(steps) > 0 {
		detail += fmt.Sprintf(", %d steps passed", len(steps))
	}
	return outcome{ok: true, detail: detail, latency: loaded, extra: extra}
}

func describeStep(s browserStep) string {
	switch {
	case s.Selector != "":
		return s.Action + " " + truncate(s.Selector, 60)
	case s.URL != "":
		return "goto " + truncate(s.URL, 60)
	case s.Text != "":
		return s.Action + " " + truncate(fmt.Sprintf("%q", s.Text), 60)
	}
	return s.Action
}

// typedText fills {{password}} and {{username}} from the check's params,
// so a secret lives in a masked field, not in the steps.
func typedText(s browserStep, p map[string]string) string {
	return strings.NewReplacer("{{password}}", p["password"], "{{username}}", p["username"]).Replace(s.Text)
}

func runStep(ctx context.Context, s browserStep, p map[string]string) error {
	var err error
	switch s.Action {
	case "goto":
		_, err = chromedp.RunResponse(ctx, chromedp.Navigate(s.URL))
	case "click":
		err = chromedp.Run(ctx, chromedp.WaitVisible(s.Selector, chromedp.ByQuery), chromedp.Click(s.Selector, chromedp.ByQuery))
	case "type":
		err = chromedp.Run(ctx, chromedp.WaitVisible(s.Selector, chromedp.ByQuery),
			chromedp.SendKeys(s.Selector, typedText(s, p), chromedp.ByQuery))
	case "wait":
		err = chromedp.Run(ctx, chromedp.WaitVisible(s.Selector, chromedp.ByQuery))
	case "expect_text", "expect_no_text":
		// Pages render late: wait up to 5 s for the text to show (or go).
		want := s.Action == "expect_text"
		deadline := time.Now().Add(5 * time.Second)
		for {
			var text string
			if err := chromedp.Run(ctx, chromedp.Evaluate(`document.body ? document.body.innerText : ""`, &text)); err != nil {
				return errors.New(browserErr(err))
			}
			if strings.Contains(text, s.Text) == want {
				return nil
			}
			if time.Now().After(deadline) || ctx.Err() != nil {
				if want {
					return errors.New("text not found on the page")
				}
				return errors.New("text still on the page")
			}
			time.Sleep(250 * time.Millisecond)
		}
	case "sleep":
		select {
		case <-time.After(time.Duration(s.Ms) * time.Millisecond):
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errors.New("timed out")
		}
		return errors.New(browserErr(err))
	}
	return nil
}

func browserErr(err error) string {
	s := cleanErr(err)
	// "page load error net::ERR_NAME_NOT_RESOLVED" reads fine on its own.
	return strings.TrimPrefix(s, "page load error ")
}

// startGuardProxy runs an HTTP proxy on loopback whose every outbound
// connection goes through the public-address guard. It answers CONNECT
// (HTTPS, WebSockets) and plain HTTP requests.
func startGuardProxy() (addr string, stop func(), err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), publicOnlyKey{}, true))
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go guardProxyConn(ctx, conn)
		}
	}()
	return ln.Addr().String(), func() { cancel(); ln.Close() }, nil
}

func guardProxyConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(maxBrowserTime))
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	d := dialer(ctx)
	if req.Method == http.MethodConnect {
		up, err := d.DialContext(ctx, "tcp", req.Host)
		if err != nil {
			_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
			return
		}
		defer up.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() { _, _ = io.Copy(up, br) }()
		_, _ = io.Copy(conn, up)
		return
	}
	// Plain HTTP: forward one request per connection.
	if req.URL.Scheme != "http" || req.URL.Host == "" {
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return
	}
	t := &http.Transport{DialContext: d.DialContext, Proxy: nil, DisableKeepAlives: true}
	defer t.CloseIdleConnections()
	req.RequestURI = ""
	req.Header.Del("Proxy-Connection")
	req.Close = true
	resp, err := t.RoundTrip(req.WithContext(ctx))
	if err != nil {
		status := "502 Bad Gateway"
		if errors.Is(err, errPrivateAddress) || strings.Contains(err.Error(), errPrivateAddress.Error()) {
			status = "403 Forbidden"
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 "+status+"\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer resp.Body.Close()
	resp.Close = true
	_ = resp.Write(conn)
}
