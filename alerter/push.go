package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	webpush "github.com/SherClockHolmes/webpush-go"
)

// pushSender delivers Web Push notifications to browsers (desktop, Android,
// and iOS home-screen apps). The channel's target is the subscription
// endpoint; its config holds the subscription's p256dh and auth keys.
type pushSender struct {
	publicKey, privateKey, subject string
	client                         *http.Client
}

// pushPayload is what the console's service worker shows.
type pushPayload struct {
	Title    string `json:"title"`
	Body     string `json:"body"`
	URL      string `json:"url,omitempty"`
	Tag      string `json:"tag,omitempty"`
	Severity string `json:"severity,omitempty"`
	Resolved bool   `json:"resolved,omitempty"`
	// One-click acknowledge from the notification (a signed link; no sign-in).
	AckURL string `json:"ack_url,omitempty"`
}

func (p *pushSender) send(context.Context, string, message) error {
	return permanent("push needs the subscription keys")
}

func (p *pushSender) sendWithConfig(ctx context.Context, endpoint string, cfg map[string]string, m message) error {
	if p.publicKey == "" || p.privateKey == "" {
		return permanent("push is not configured (VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY)")
	}
	if !strings.HasPrefix(endpoint, "https://") || cfg["p256dh"] == "" || cfg["auth"] == "" {
		return permanent("invalid push subscription")
	}
	body, err := json.Marshal(pushContent(m))
	if err != nil {
		return err
	}
	ttl := 24 * 3600
	resp, err := webpush.SendNotificationWithContext(ctx, body, &webpush.Subscription{
		Endpoint: endpoint,
		Keys:     webpush.Keys{P256dh: cfg["p256dh"], Auth: cfg["auth"]},
	}, &webpush.Options{
		HTTPClient:      p.client,
		Subscriber:      p.subject,
		VAPIDPublicKey:  p.publicKey,
		VAPIDPrivateKey: p.privateKey,
		TTL:             ttl,
		Urgency:         urgency(m),
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
	switch {
	case resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusGone || resp.StatusCode == http.StatusNotFound:
		// The browser unsubscribed; the API removes such channels.
		return &goneError{permanentError{msg: "push subscription expired"}}
	case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusRequestEntityTooLarge:
		return permanent("push service rejected the message: %s %s", resp.Status, msg)
	default:
		return &httpStatusError{status: resp.Status, body: string(msg)}
	}
}

// goneError marks a subscription the browser has dropped.
type goneError struct{ permanentError }

func (e *goneError) Unwrap() error { return &e.permanentError }

type httpStatusError struct{ status, body string }

func (e *httpStatusError) Error() string { return "push service returned " + e.status + ": " + e.body }

func pushContent(m message) pushPayload {
	p := pushPayload{Title: m.Subject, Body: firstLines(m.Text, 3)}
	p.Title = strings.TrimPrefix(p.Title, "[Sentinel] ")
	if m.Event != nil {
		if v, ok := m.Event["summary"].(string); ok && v != "" {
			p.Title = v
		}
		if v, ok := m.Event["condition"].(string); ok && v != "" {
			p.Body = v
			if d, ok := m.Event["detail"].(string); ok && d != "" {
				p.Body += "\n" + d
			}
		}
		p.URL, _ = m.Event["url"].(string)
		p.Severity, _ = m.Event["severity"].(string)
		if id, ok := m.Event["incident_id"].(string); ok && id != "" {
			// Same tag: the "resolved" notification replaces the "firing" one.
			p.Tag = "incident-" + id
		}
		switch m.Event["type"] {
		case "alert_resolved":
			p.Resolved = true
			p.Title = "✓ " + p.Title
		case "alert_escalation":
			p.Title = "Escalated: " + p.Title
		}
	}
	if !p.Resolved {
		p.AckURL = extractLink(m.Text, "Acknowledge (stops escalation): ")
	}
	p.Body = cut(p.Body, 1000)
	return p
}

func urgency(m message) webpush.Urgency {
	if m.Event != nil {
		if m.Event["type"] == "alert_resolved" {
			return webpush.UrgencyNormal
		}
		if m.Event["severity"] == "critical" || m.Event["type"] == "alert_escalation" {
			return webpush.UrgencyHigh
		}
	}
	return webpush.UrgencyNormal
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	var out []string
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		out = append(out, l)
		if len(out) == n {
			break
		}
	}
	return strings.Join(out, "\n")
}
