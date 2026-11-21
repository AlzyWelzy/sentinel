package checks

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AlzyWelzy/sentinel/proto"
)

func TestHTTPThroughProxy(t *testing.T) {
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// A forward proxy sees the absolute URL.
		if req.URL.Host == "site.invalid" {
			proxied.Add(1)
			_, _ = w.Write([]byte("hello via proxy"))
			return
		}
		http.Error(w, "unexpected", 502)
	}))
	defer proxy.Close()
	r := NewRunner("test")
	c := proto.Check{ID: "p", Type: "http", Target: "http://site.invalid/", Params: map[string]string{
		"proxy": proxy.URL, "keyword": "via proxy"}}
	if res := runOne(t, r, c); !res.OK || proxied.Load() != 1 {
		t.Fatalf("through the proxy: %+v (proxied %d)", res, proxied.Load())
	}
	c.ID, c.Params = "q", map[string]string{"proxy": "ftp://x:1"}
	if res := runOne(t, r, c); res.OK || !strings.Contains(res.Detail, "proxy must be") {
		t.Fatalf("bad proxy scheme: %+v", res)
	}
	// On a public probe the proxy itself must be public.
	c.ID, c.Params = "r", map[string]string{"proxy": proxy.URL, "public_only": "true"}
	if res := runOne(t, r, c); res.OK || !strings.Contains(res.Detail, "private") {
		t.Fatalf("private proxy from a probe: %+v", res)
	}
}

func TestHTTPClientCertificate(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if len(req.TLS.PeerCertificates) == 0 {
			http.Error(w, "no client cert", 401)
			return
		}
		_, _ = w.Write([]byte("hi " + req.TLS.PeerCertificates[0].Subject.CommonName))
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	// The test server's own certificate doubles as a client certificate.
	leaf := srv.TLS.Certificates[0]
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	r := NewRunner("test")
	base := map[string]string{"tls_skip_verify": "true"}
	if res := runOne(t, r, proto.Check{ID: "a", Type: "http", Target: srv.URL, Params: base}); res.OK {
		t.Fatalf("without a certificate it should fail: %+v", res)
	}
	with := map[string]string{"tls_skip_verify": "true", "client_cert": string(certPEM), "client_key": string(keyPEM)}
	if res := runOne(t, r, proto.Check{ID: "b", Type: "http", Target: srv.URL, Params: with}); !res.OK {
		t.Fatalf("with the certificate: %+v", res)
	}
	bad := map[string]string{"client_cert": string(certPEM), "client_key": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"}
	if res := runOne(t, r, proto.Check{ID: "c", Type: "http", Target: srv.URL, Params: bad}); res.OK || !strings.Contains(res.Detail, "don't load") {
		t.Fatalf("a broken key: %+v", res)
	}
}

func TestHTTPOAuth(t *testing.T) {
	var issued atomic.Int32
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_ = req.ParseForm()
		id, secret, basic := req.BasicAuth()
		if req.Form.Get("client_id") != "" {
			id, secret = req.Form.Get("client_id"), req.Form.Get("client_secret")
		}
		if req.Form.Get("grant_type") != "client_credentials" || id != "app" || secret != "s3cret" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"bad s3cret? no: wrong"}`))
			return
		}
		_ = basic
		issued.Add(1)
		_, _ = w.Write([]byte(`{"access_token":"tok-` + req.Form.Get("scope") + `","expires_in":3600}`))
	}))
	defer idp.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer tok-read" {
			http.Error(w, "no", 401)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer api.Close()

	r := NewRunner("test")
	p := map[string]string{"oauth_token_url": idp.URL, "oauth_client_id": "app", "oauth_client_secret": "s3cret", "oauth_scopes": "read"}
	for i := range 3 {
		if res := runOne(t, r, proto.Check{ID: "o", Type: "http", Target: api.URL, Params: p}); !res.OK {
			t.Fatalf("run %d: %+v", i, res)
		}
	}
	if issued.Load() != 1 {
		t.Fatalf("token should be reused, issued %d", issued.Load())
	}
	post := map[string]string{"oauth_token_url": idp.URL, "oauth_client_id": "app", "oauth_client_secret": "s3cret",
		"oauth_scopes": "read", "oauth_auth_method": "post"}
	if res := runOne(t, r, proto.Check{ID: "p", Type: "http", Target: api.URL, Params: post}); !res.OK {
		t.Fatalf("client_secret_post: %+v", res)
	}
	wrong := map[string]string{"oauth_token_url": idp.URL, "oauth_client_id": "app", "oauth_client_secret": "s3cret-x"}
	res := runOne(t, r, proto.Check{ID: "w", Type: "http", Target: api.URL, Params: wrong})
	if res.OK || !strings.Contains(res.Detail, "invalid_client") || strings.Contains(res.Detail, "s3cret-x") {
		t.Fatalf("wrong secret: %+v", res)
	}
}
