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
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/netip"
	"net/smtp"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// message is what's stored in outbound_messages.payload. Code is kept apart
// from Text so the dispatcher can wipe it once delivered.
type message struct {
	Subject string `json:"subject"`
	Text    string `json:"text"`
	// HTML, when set (reports), is the email's HTML part as is; otherwise
	// alerts get one rendered from Event.
	HTML  string         `json:"html,omitempty"`
	Code  string         `json:"code,omitempty"`
	Event map[string]any `json:"event,omitempty"`
}

func (m message) render() (subject, text string) {
	return m.Subject, strings.ReplaceAll(m.Text, "{{code}}", m.Code)
}

// permanentError means retrying can't help (bad address, provider not set up).
type permanentError struct{ msg string }

func (e *permanentError) Error() string { return e.msg }

// undeliverableError is a permanent rejection of the address itself (the
// mail server refused the recipient): the contact stops receiving until
// it's verified again.
type undeliverableError struct{ permanentError }

func (e *undeliverableError) Unwrap() error { return &e.permanentError }

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
	subject, text := m.render()
	return e.sendMail(ctx, to, subject, text, renderHTML(m))
}

// sendMail sends one message, with an HTML part when html isn't empty.
// Alerts and account emails (verify, reset, invitations) both go out here.
// buildMessage writes the email. Parts are quoted-printable, so a long log
// line or detail can't exceed SMTP's 998-byte line limit (strict servers
// refuse such mail), and the subject's encoded words are folded onto lines
// of their own for the same reason.
func buildMessage(from, to, subject, text, html string, now time.Time) *bytes.Buffer {
	var body bytes.Buffer
	encoded := strings.ReplaceAll(mime.QEncoding.Encode("utf-8", subject), "?= =?", "?=\r\n =?")
	fmt.Fprintf(&body, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\n",
		from, to, encoded, now.Format(time.RFC1123Z))
	body.WriteString("MIME-Version: 1.0\r\n")
	part := func(contentType, content string) {
		fmt.Fprintf(&body, "Content-Type: %s; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n", contentType)
		qp := quotedprintable.NewWriter(&body)
		qp.Write([]byte(strings.ReplaceAll(content, "\n", "\r\n")))
		qp.Close()
	}
	if html == "" {
		part("text/plain", text)
		return &body
	}
	const boundary = "sentinel-alternative-boundary"
	fmt.Fprintf(&body, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)
	fmt.Fprintf(&body, "--%s\r\n", boundary)
	part("text/plain", text)
	fmt.Fprintf(&body, "\r\n--%s\r\n", boundary)
	part("text/html", html)
	fmt.Fprintf(&body, "\r\n--%s--\r\n", boundary)
	return &body
}

func (e *emailSender) sendMail(ctx context.Context, to, subject, text, html string) error {
	if e.host == "" {
		return permanent("email is not configured (SMTP_HOST)")
	}
	if strings.ContainsAny(to, "\r\n") || !strings.Contains(to, "@") {
		return permanent("invalid email address")
	}
	body := buildMessage(e.from, to, subject, text, html, time.Now())

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
		return &undeliverableError{permanentError{msg: fmt.Sprintf("recipient rejected: %v", err)}}
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

// publicIP matches the agent's probe guard (agent/checks/guard.go): no
// loopback, private, link-local, CGNAT or reserved ranges, and a NAT64
// address is judged by the IPv4 address it reaches.
func publicIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if nat64.Contains(addr) {
		b := addr.As16()
		addr = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() || addr.IsUnspecified() || addr.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

var (
	nat64     = netip.MustParsePrefix("64:ff9b::/96")
	nonPublic = []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"),  // carrier-grade NAT
		netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments
		netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking
		netip.MustParsePrefix("0.0.0.0/8"),      // "this network"
		netip.MustParsePrefix("240.0.0.0/4"),    // reserved
		netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64
		netip.MustParsePrefix("2001:db8::/32"),  // documentation
	}
)

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
	req.Header.Set("User-Agent", "Sentinel-Webhook/1")
	if w.signingSecret != "" {
		mac := hmac.New(sha256.New, []byte(w.signingSecret))
		mac.Write(body)
		req.Header.Set("X-Sentinel-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
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
	text = cut(text, 1500)
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
