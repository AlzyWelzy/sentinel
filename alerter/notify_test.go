package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebhookRefusesPrivateAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("request reached a private address")
	}))
	defer srv.Close()

	w := newWebhookSender("", false)
	for _, target := range []string{srv.URL, "http://localhost:8428/api/v1/admin/tsdb/delete_series"} {
		err := w.send(context.Background(), target, message{Subject: "x", Text: "y"})
		var perm *permanentError
		if !errors.As(err, &perm) {
			t.Errorf("%s: want permanent refusal, got %v", target, err)
		}
	}
}

func TestWebhookSignsBody(t *testing.T) {
	var sig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sig = r.Header.Get("X-Pulsegrid-Signature")
	}))
	defer srv.Close()
	if err := newWebhookSender("secret", true).send(context.Background(), srv.URL, message{Subject: "s"}); err != nil {
		t.Fatal(err)
	}
	if len(sig) != len("sha256=")+64 {
		t.Fatalf("missing or malformed signature: %q", sig)
	}
}

func TestPublicIP(t *testing.T) {
	for _, s := range []string{"10.0.0.1", "172.23.2.12", "192.168.1.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "fd00::1"} {
		if publicIP(net.ParseIP(s)) {
			t.Errorf("%s treated as public", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "103.129.97.5", "2606:4700::1111"} {
		if !publicIP(net.ParseIP(s)) {
			t.Errorf("%s treated as private", s)
		}
	}
}

func TestCodeRendering(t *testing.T) {
	_, text := message{Text: "Your code is {{code}}", Code: "123456"}.render()
	if text != "Your code is 123456" {
		t.Fatal(text)
	}
}

func TestConsoleMailer(t *testing.T) {
	var got map[string]string
	var key string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key = r.Header.Get("X-Internal-Api-Key")
		json.NewDecoder(r.Body).Decode(&got)
	}))
	defer srv.Close()

	m := &consoleMailer{url: srv.URL, apiKey: "k", client: srv.Client()}
	if err := m.send(context.Background(), "ops@example.com", message{Subject: "s", Text: "code {{code}}", Code: "123456"}); err != nil {
		t.Fatal(err)
	}
	if key != "k" || got["to"] != "ops@example.com" || got["text"] != "code 123456" || got["purpose"] != "monitoring" {
		t.Fatalf("unexpected request: key=%q body=%v", key, got)
	}
}

func TestConsoleMailerErrorsClassified(t *testing.T) {
	for status, wantPermanent := range map[int]bool{400: true, 422: true, 401: false, 500: false, 503: false} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		err := (&consoleMailer{url: srv.URL, client: srv.Client()}).send(context.Background(), "a@b.co", message{})
		srv.Close()
		var perm *permanentError
		if err == nil || errors.As(err, &perm) != wantPermanent {
			t.Errorf("status %d: err=%v, want permanent=%v", status, err, wantPermanent)
		}
	}
}
