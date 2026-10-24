package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// message is what's stored in outbound_messages.payload. Code is kept apart
// from Text so the dispatcher can wipe it once delivered.
type message struct {
	Subject string         `json:"subject"`
	Text    string         `json:"text"`
	Code    string         `json:"code,omitempty"`
	Event   map[string]any `json:"event,omitempty"`
}

func (m message) render() (subject, text string) {
	return m.Subject, strings.ReplaceAll(m.Text, "{{code}}", m.Code)
}

// permanentError means retrying can't help (bad address, provider not set up).
type permanentError struct{ msg string }

func (e *permanentError) Error() string { return e.msg }

func permanent(format string, args ...any) error {
	return &permanentError{msg: fmt.Sprintf(format, args...)}
}

type sender interface {
	send(ctx context.Context, target string, m message) error
}

// configSender is a sender that also needs the channel's stored config
// (push subscriptions carry their encryption keys there).
type configSender interface {
	sendWithConfig(ctx context.Context, target string, cfg map[string]string, m message) error
}

// ── Email (SMTP) ─────────────────────────────────────────────────────────────

type emailSender struct {
	host, port, username, password, from string
	tlsMode                              string // "starttls", "tls" (implicit, port 465) or "none"
}

func (e *emailSender) send(ctx context.Context, to string, m message) error {
	if e.host == "" {
		return permanent("email is not configured (SMTP_HOST)")
	}
	if strings.ContainsAny(to, "\r\n") || !strings.Contains(to, "@") {
		return permanent("invalid email address")
	}
	subject, text := m.render()
	var body bytes.Buffer
	fmt.Fprintf(&body, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\n",
		e.from, to, mime.QEncoding.Encode("utf-8", subject), time.Now().Format(time.RFC1123Z))
	body.WriteString("MIME-Version: 1.0\r\n")
	if html := renderHTML(m); html != "" {
		const boundary = "pulsegrid-alternative-boundary"
		fmt.Fprintf(&body, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)
		fmt.Fprintf(&body, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n", boundary)
		body.WriteString(strings.ReplaceAll(text, "\n", "\r\n"))
		fmt.Fprintf(&body, "\r\n--%s\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n", boundary)
		body.WriteString(strings.ReplaceAll(html, "\n", "\r\n"))
		fmt.Fprintf(&body, "\r\n--%s--\r\n", boundary)
	} else {
		body.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		body.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
		body.WriteString(strings.ReplaceAll(text, "\n", "\r\n"))
	}

	addr := net.JoinHostPort(e.host, e.port)
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	var err error
	if e.tlsMode == "tls" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: e.host})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	c, err := smtp.NewClient(conn, e.host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if e.tlsMode == "starttls" {
		if err := c.StartTLS(&tls.Config{ServerName: e.host}); err != nil {
			return err
		}
	}
	if e.username != "" {
		if err := c.Auth(smtp.PlainAuth("", e.username, e.password, e.host)); err != nil {
			return err
		}
	}
	if err := c.Mail(addressOnly(e.from)); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return permanent("recipient rejected: %v", err)
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(body.Bytes()); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func addressOnly(from string) string {
	if i := strings.LastIndex(from, "<"); i >= 0 {
		return strings.TrimSuffix(from[i+1:], ">")
	}
	return from
}

// ── Email through the console ────────────────────────────────────────────────

// consoleMailer hands email to the console backend, which sends it with the
// mail settings configured there (Office 365 / SES, from-address per purpose),
// so mail credentials live in one place and Pulsegrid never holds them.
type consoleMailer struct {
	url    string // e.g. http://console-backend:8000/api/internal/pulsegrid/email/
	apiKey string
	client *http.Client
}

func (c *consoleMailer) send(ctx context.Context, to string, m message) error {
	if c.url == "" {
		return permanent("console email is not configured (CONSOLE_EMAIL_URL)")
	}
	if strings.ContainsAny(to, "\r\n") || !strings.Contains(to, "@") {
		return permanent("invalid email address")
	}
	subject, text := m.render()
	body, err := json.Marshal(map[string]string{
		"to": to, "subject": subject, "text": text, "html": renderHTML(m), "purpose": "monitoring",
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return permanent("invalid CONSOLE_EMAIL_URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Api-Key", c.apiKey)
	resp, err := c.client.Do(req)
	if err != nil {
		return err // console unreachable: retried with backoff
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	switch {
	case resp.StatusCode < 300:
		return nil
	case resp.StatusCode == 400 || resp.StatusCode == 422:
		return permanent("console rejected the email: %s", msg)
	default:
		// 401/403 (key mismatch) and 5xx can be fixed on the console side
		// without losing the alert, so they're retried.
		return fmt.Errorf("console email endpoint returned %s: %s", resp.Status, msg)
	}
}

// ── Webhook ──────────────────────────────────────────────────────────────────

type webhookSender struct {
	client        *http.Client
	signingSecret string
}

// newWebhookSender returns a sender whose connections refuse private,
// loopback and link-local addresses (checked after DNS resolution, so a
// hostname pointing inward is caught too), unless allowPrivate is set for
// local development.
func newWebhookSender(signingSecret string, allowPrivate bool) *webhookSender {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if !allowPrivate {
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || !publicIP(ip) {
				return permanent("webhook address %s is not a public IP", host)
			}
			return nil
		}
	}
	transport := &http.Transport{DialContext: dialer.DialContext, Proxy: nil}
	return &webhookSender{
		signingSecret: signingSecret,
		client: &http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse // a redirect could point inward
			},
		},
	}
}

func publicIP(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsInterfaceLocalMulticast() || isCGNAT(ip))
}

func isCGNAT(ip net.IP) bool {
	_, cgnat, _ := net.ParseCIDR("100.64.0.0/10")
	return cgnat.Contains(ip)
}

func (w *webhookSender) send(ctx context.Context, target string, m message) error {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return permanent("invalid webhook URL")
	}
	subject, text := m.render()
	body, err := json.Marshal(map[string]any{
		"subject": subject,
		"text":    text,
		"event":   m.Event,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return permanent("invalid webhook URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Pulsegrid-Webhook/1")
	if w.signingSecret != "" {
		mac := hmac.New(sha256.New, []byte(w.signingSecret))
		mac.Write(body)
		req.Header.Set("X-Pulsegrid-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := w.client.Do(req)
	if err != nil {
		var perm *permanentError
		if errors.As(err, &perm) {
			return perm
		}
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode < 300:
		return nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429:
		return permanent("webhook returned %s", resp.Status)
	default:
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
}

// ── SMS (Twilio) ─────────────────────────────────────────────────────────────

type smsSender struct {
	accountSID, authToken, from string
	client                      *http.Client
}

func (s *smsSender) send(ctx context.Context, to string, m message) error {
	if s.accountSID == "" {
		return permanent("SMS is not configured (TWILIO_ACCOUNT_SID)")
	}
	_, text := m.render()
	if len(text) > 1500 {
		text = text[:1500]
	}
	form := url.Values{"To": {to}, "From": {s.from}, "Body": {text}}
	endpoint := "https://api.twilio.com/2010-04-01/Accounts/" + url.PathEscape(s.accountSID) + "/Messages.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth(s.accountSID, s.authToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	switch {
	case resp.StatusCode < 300:
		return nil
	case resp.StatusCode == 400:
		return permanent("SMS rejected: %s", msg)
	default:
		return fmt.Errorf("SMS provider returned %s: %s", resp.Status, msg)
	}
}
