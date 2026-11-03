package main

import (
	"context"
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
		sig = r.Header.Get("X-Sentinel-Signature")
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
	for _, s := range []string{"10.0.0.1", "172.23.2.12", "192.168.1.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "fd00::1",
		"0.1.2.3", "198.18.0.1", "240.0.0.1", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe"} {
		if publicIP(net.ParseIP(s)) {
			t.Errorf("%s treated as public", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "103.129.97.5", "2606:4700::1111", "64:ff9b::808:808"} {
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
