package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Senders for chat and paging services. Slack, Teams and Discord URLs come
// from customers, so they go through the webhook sender's client, which
// refuses private addresses. Telegram, PagerDuty and Twilio are fixed public
// APIs (their base URLs are configurable only so tests can stand them in).

// postJSON sends body and maps the response the way every sender here needs:
// 2xx sent, other 4xx (except 429) permanent, anything else retried.
func postJSON(ctx context.Context, client *http.Client, target string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(b))
	if err != nil {
		return permanent("invalid URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Sentinel/1")
	resp, err := client.Do(req)
	if err != nil {
		var perm *permanentError
		if errors.As(err, &perm) {
			return perm
		}
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	switch {
	case resp.StatusCode < 300:
		return nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429:
		return permanent("%s returned %s: %s", hostOf(target), resp.Status, bytes.TrimSpace(msg))
	default:
		return fmt.Errorf("%s returned %s: %s", hostOf(target), resp.Status, bytes.TrimSpace(msg))
	}
}

// hostOf names the service in errors without the secret part of the URL.
func hostOf(target string) string {
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		return u.Host
	}
	return "endpoint"
}

// ── Slack ────────────────────────────────────────────────────────────────────

type slackSender struct{ client *http.Client }

func (s *slackSender) send(ctx context.Context, target string, m message) error {
	subject, text := m.render()
	return postJSON(ctx, s.client, target, map[string]any{"text": "*" + subject + "*\n" + text})
}

// ── Microsoft Teams ──────────────────────────────────────────────────────────

// teamsSender posts an Adaptive Card, which both Teams Workflows webhooks and
// the older Office 365 connector webhooks accept.
type teamsSender struct{ client *http.Client }

func (s *teamsSender) send(ctx context.Context, target string, m message) error {
	subject, text := m.render()
	card := map[string]any{
		"type":    "AdaptiveCard",
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"version": "1.4",
		"body": []map[string]any{
			{"type": "TextBlock", "text": subject, "weight": "Bolder", "size": "Medium", "wrap": true},
			{"type": "TextBlock", "text": text, "wrap": true},
		},
	}
	return postJSON(ctx, s.client, target, map[string]any{
		"type": "message",
		"attachments": []map[string]any{
			{"contentType": "application/vnd.microsoft.card.adaptive", "content": card},
		},
	})
}

// ── Discord ──────────────────────────────────────────────────────────────────

type discordSender struct{ client *http.Client }

func (s *discordSender) send(ctx context.Context, target string, m message) error {
	subject, text := m.render()
	content := "**" + subject + "**\n" + text
	if len(content) > 1990 {
		content = content[:1990]
	}
	return postJSON(ctx, s.client, target, map[string]any{"content": content, "username": "Sentinel"})
}

// ── Telegram ─────────────────────────────────────────────────────────────────

// telegramSender sends through the customer's own bot. The target is
// "<bot token>/<chat id>" (a chat id is a number, or @channelname).
type telegramSender struct {
	client  *http.Client
	baseURL string // https://api.telegram.org
}

func (s *telegramSender) send(ctx context.Context, target string, m message) error {
	token, chat, ok := strings.Cut(target, "/")
	if !ok || token == "" || chat == "" {
		return permanent("invalid Telegram target")
	}
	subject, text := m.render()
	// HTML mode, escaped, so alert text can't be read as markup.
	body := map[string]any{
		"chat_id":                  chat,
		"text":                     "<b>" + html.EscapeString(subject) + "</b>\n" + html.EscapeString(text),
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	}
	return postJSON(ctx, s.client, strings.TrimRight(s.baseURL, "/")+"/bot"+token+"/sendMessage", body)
}

// ── PagerDuty (Events API v2) ────────────────────────────────────────────────

// pagerDutySender triggers and resolves PagerDuty incidents, one per
// Sentinel incident (dedup_key), so PagerDuty's own escalation and
// acknowledgement take over. The target is an integration (routing) key.
type pagerDutySender struct {
	client *http.Client
	url    string // https://events.pagerduty.com/v2/enqueue
}

func (s *pagerDutySender) send(ctx context.Context, target string, m message) error {
	subject, text := m.render()
	kind, _ := m.Event["type"].(string)
	dedup, _ := m.Event["incident_id"].(string)
	if dedup == "" {
		channel, _ := m.Event["channel_id"].(string)
		dedup = "sentinel-" + kind + "-" + channel
	}
	event := func(action string) map[string]any {
		e := map[string]any{"routing_key": target, "event_action": action, "dedup_key": dedup}
		if action == "trigger" {
			source, _ := m.Event["hostname"].(string)
			if source == "" {
				source = "sentinel"
			}
			severity := "critical"
			if kind == "verification" || kind == "test" {
				severity = "info"
			}
			e["payload"] = map[string]any{
				"summary":        truncate(subject, 1024),
				"source":         source,
				"severity":       severity,
				"custom_details": map[string]any{"text": text},
			}
		}
		return e
	}
	switch kind {
	case "alert_resolved":
		return postJSON(ctx, s.client, s.url, event("resolve"))
	case "verification", "test":
		// Shows up in PagerDuty (with the code), then closes itself, so a
		// test never leaves someone paged.
		if err := postJSON(ctx, s.client, s.url, event("trigger")); err != nil {
			return err
		}
		return postJSON(ctx, s.client, s.url, event("resolve"))
	default:
		return postJSON(ctx, s.client, s.url, event("trigger"))
	}
}

// ── Voice (Twilio) ───────────────────────────────────────────────────────────

// voiceSender phones the target and reads the alert out twice. For a
// verification code it reads the digits one at a time.
type voiceSender struct {
	accountSID, authToken, from string
	client                      *http.Client
	baseURL                     string // https://api.twilio.com
}

func (s *voiceSender) send(ctx context.Context, to string, m message) error {
	if s.accountSID == "" {
		return permanent("voice calls are not configured (TWILIO_ACCOUNT_SID)")
	}
	form := url.Values{"To": {to}, "From": {s.from}, "Twiml": {voiceTwiML(m)}}
	endpoint := strings.TrimRight(s.baseURL, "/") + "/2010-04-01/Accounts/" + url.PathEscape(s.accountSID) + "/Calls.json"
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
		return permanent("call rejected: %s", msg)
	default:
		return fmt.Errorf("voice provider returned %s: %s", resp.Status, msg)
	}
}

func voiceTwiML(m message) string {
	var say string
	if m.Code != "" {
		say = "Your Sentinel verification code is " + strings.Join(strings.Split(m.Code, ""), ", ") + "."
	} else {
		subject := strings.TrimPrefix(m.Subject, "[Sentinel] ")
		say = "This is a Sentinel alert. " + subject + ". Please check your dashboard."
	}
	say = html.EscapeString(say)
	return `<Response><Say voice="alice">` + say + `</Say><Pause length="1"/><Say voice="alice">` + say + `</Say></Response>`
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
