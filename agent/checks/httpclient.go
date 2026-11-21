package checks

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/AlzyWelzy/sentinel/proto"
)

// httpClient is the client an HTTP check uses: the shared one, or its own
// transport when it skips certificate checks, runs on a public probe (every
// connection, the proxy's too, goes through the address guard), goes
// through a proxy, or presents a client certificate.
func (r *Runner) httpClient(ctx context.Context, c proto.Check) (*http.Client, error) {
	p := c.Params
	if p["tls_skip_verify"] != "true" && p["public_only"] != "true" && p["proxy"] == "" && p["client_cert"] == "" {
		return r.client, nil
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if p["tls_skip_verify"] == "true" {
		t.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec // the user asked for it
	}
	if p["public_only"] == "true" {
		t.DialContext = dialer(ctx).DialContext
		t.Proxy = nil
	}
	if raw := p["proxy"]; raw != "" {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return nil, errors.New("proxy must be a URL like http://proxy:3128 or socks5://proxy:1080")
		}
		switch u.Scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return nil, errors.New("proxy must be http, https, socks5 or socks5h")
		}
		t.Proxy = http.ProxyURL(u)
		if t.DialContext == nil || p["public_only"] != "true" {
			t.DialContext = dialer(ctx).DialContext
		}
	}
	if p["client_cert"] != "" {
		cert, err := tls.X509KeyPair([]byte(p["client_cert"]), []byte(p["client_key"]))
		if err != nil {
			return nil, errors.New("the client certificate and key don't load (PEM, and a matching pair)")
		}
		t.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}
	return &http.Client{Timeout: r.client.Timeout, Transport: t, CheckRedirect: r.client.CheckRedirect}, nil
}

type cachedToken struct {
	token   string
	expires time.Time
}

var (
	tokensMu sync.Mutex
	tokens   = map[string]cachedToken{}
)

// oauthToken gets an access token with the client credentials grant and
// keeps it until shortly before it expires. Errors never carry the secret.
func oauthToken(ctx context.Context, client *http.Client, p map[string]string) (string, error) {
	sum := sha256.Sum256([]byte(strings.Join([]string{p["oauth_token_url"], p["oauth_client_id"],
		p["oauth_client_secret"], p["oauth_scopes"], p["oauth_auth_method"]}, "\x00")))
	key := hex.EncodeToString(sum[:])
	tokensMu.Lock()
	if t, ok := tokens[key]; ok && time.Now().Before(t.expires) {
		tokensMu.Unlock()
		return t.token, nil
	}
	tokensMu.Unlock()

	form := url.Values{"grant_type": {"client_credentials"}}
	if s := p["oauth_scopes"]; s != "" {
		form.Set("scope", s)
	}
	post := p["oauth_auth_method"] == "post"
	if post {
		form.Set("client_id", p["oauth_client_id"])
		form.Set("client_secret", p["oauth_client_secret"])
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p["oauth_token_url"], strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.New("invalid token URL")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if !post {
		req.SetBasicAuth(url.QueryEscape(p["oauth_client_id"]), url.QueryEscape(p["oauth_client_secret"]))
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %s", cleanErr(err))
	}
	defer resp.Body.Close()
	var body struct {
		AccessToken string      `json:"access_token"`
		ExpiresIn   json.Number `json:"expires_in"`
		Error       string      `json:"error"`
		Description string      `json:"error_description"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = json.Unmarshal(raw, &body)
	if resp.StatusCode/100 != 2 || body.AccessToken == "" {
		why := body.Error
		if body.Description != "" {
			why += ": " + body.Description
		}
		if why == "" {
			why = "no access_token in the answer"
		}
		why = strings.ReplaceAll(why, p["oauth_client_secret"], "[secret]")
		return "", fmt.Errorf("token request: HTTP %d, %s", resp.StatusCode, truncate(why, 120))
	}
	life := 300 * time.Second
	if n, err := body.ExpiresIn.Int64(); err == nil && n > 0 {
		life = time.Duration(n) * time.Second
	}
	// Refresh a little early, but never cache for less than ten seconds.
	life = max(life-30*time.Second, 10*time.Second)
	tokensMu.Lock()
	if len(tokens) > 1000 {
		tokens = map[string]cachedToken{}
	}
	tokens[key] = cachedToken{token: body.AccessToken, expires: time.Now().Add(life)}
	tokensMu.Unlock()
	return body.AccessToken, nil
}
