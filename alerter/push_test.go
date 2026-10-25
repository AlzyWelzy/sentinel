package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	webpush "github.com/SherClockHolmes/webpush-go"
)

func TestPushSender(t *testing.T) {
	priv, pub, err := webpush.GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	var gotAuth, gotEncoding string
	var gotBody int
	status := http.StatusCreated
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotEncoding = r.Header.Get("Authorization"), r.Header.Get("Content-Encoding")
		b, _ := io.ReadAll(r.Body)
		gotBody = len(b)
		w.WriteHeader(status)
	}))
	defer srv.Close()
	// A real browser subscription's keys (from the Web Push test vectors).
	cfg := map[string]string{
		"p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM",
		"auth":   "tBHItJI5svbpez7KI4CCXg",
	}
	p := &pushSender{publicKey: pub, privateKey: priv, subject: "mailto:t@example.com", client: srv.Client()}
	m := message{Subject: "[Pulsegrid] FIRING: x", Text: "x", Event: map[string]any{
		"type": "alert_firing", "summary": "nginx is down on web1", "condition": "Service nginx is stopped",
		"severity": "critical", "incident_id": "i1", "url": "https://console/x"}}
	if err := p.sendWithConfig(context.Background(), srv.URL, cfg, m); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(gotAuth, "vapid t=") || gotEncoding != "aes128gcm" || gotBody == 0 {
		t.Fatalf("auth=%q encoding=%q body=%d", gotAuth, gotEncoding, gotBody)
	}
	status = http.StatusGone
	err = p.sendWithConfig(context.Background(), srv.URL, cfg, m)
	var gone *goneError
	var perm *permanentError
	if !errors.As(err, &gone) || !errors.As(err, &perm) {
		t.Fatalf("410 should be a permanent gone error, got %v", err)
	}
	if err := p.sendWithConfig(context.Background(), "http://insecure", cfg, m); err == nil {
		t.Fatal("non-https endpoint must be refused")
	}
	c := pushContent(m)
	if c.Title != "nginx is down on web1" || c.Tag != "incident-i1" || c.URL != "https://console/x" {
		t.Fatalf("%+v", c)
	}
}

func TestRenderHTML(t *testing.T) {
	m := message{Text: "Acknowledge (stops escalation): https://api/ack/tok\n", Event: map[string]any{
		"type": "alert_firing", "summary": "<script>x</script>", "severity": "warning", "url": "https://c/i"}}
	h := renderHTML(m)
	if strings.Contains(h, "<script>x") || !strings.Contains(h, "&lt;script&gt;") {
		t.Fatal("summary not escaped")
	}
	if !strings.Contains(h, "https://api/ack/tok") || !strings.Contains(h, "#d97706") {
		t.Fatal("missing ack link or warning colour")
	}
	if renderHTML(message{Text: "code 123"}) != "" {
		t.Fatal("plain messages have no html")
	}
}
