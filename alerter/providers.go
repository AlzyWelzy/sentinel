package main

// Catalog providers: every notification service that takes one HTTP
// request per alert is described in proto/notifiers.json, and this one
// sender delivers for all of them. A channel's form fields are in its
// config; the request's URL, headers and body are templates over those
// fields and the alert.
//
// Template values: every field by its key, and title, text, summary,
// severity, status (firing, resolved, reminder, escalation, test), host,
// rule, incident_id, link, emoji, nonce (random hex), ts and ts_ms (now, in
// seconds and milliseconds, the same in every template of one send).
// Functions: sev "critical" "warning" "info" picks by severity; res
// "firing" "resolved" by whether it's a recovery; path and query escape for
// URLs; trunc n cuts to n characters; b64; hmac256 and hmac256b64 key msg
// (hex and base64); prefix s p reports whether s starts with p; between
// s a b is what follows a in s up to b.
//
// JSON body leaves are templates too. "int:…", "float:…" and "bool:…"
// leaves become numbers and booleans, "list:…" a list (split on commas),
// and "opt:…" leaves (and headers) that render empty are left out.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/AlzyWelzy/sentinel/proto"
)

type catalogSender struct {
	def    proto.Notifier
	client *http.Client
	mu     sync.Mutex
	cache  map[string]*template.Template
	tokens map[string]oauthToken // OAuth client: token URL + client id + scope
}

type oauthToken struct {
	value   string
	expires time.Time
}

func catalogSenders(client *http.Client) (map[string]sender, error) {
	defs, err := proto.Notifiers()
	if err != nil {
		return nil, err
	}
	out := map[string]sender{}
	for _, d := range defs {
		if d.Request.Format == "nostr" {
			out[d.Type] = &nostrSender{def: d}
			continue
		}
		out[d.Type] = &catalogSender{
			def: d, client: client, cache: map[string]*template.Template{}, tokens: map[string]oauthToken{},
		}
	}
	return out, nil
}

func (s *catalogSender) send(ctx context.Context, target string, m message) error {
	return s.sendWithConfig(ctx, target, nil, m)
}

var templateFuncs = template.FuncMap{
	"path":   url.PathEscape,
	"query":  url.QueryEscape,
	"trunc":  func(n int, s string) string { return cut(s, n) },
	"b64":    func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) },
	"prefix": strings.HasPrefix,
	// between s a b: what follows a in s, up to the next b.
	"between": func(s, a, b string) string {
		_, after, ok := strings.Cut(s, a)
		if !ok {
			return ""
		}
		before, _, _ := strings.Cut(after, b)
		return before
	},
	"hmac256": func(key, msg string) string {
		h := hmac.New(sha256.New, []byte(key))
		h.Write([]byte(msg))
		return hex.EncodeToString(h.Sum(nil))
	},
	"hmac256b64": func(key, msg string) string {
		h := hmac.New(sha256.New, []byte(key))
		h.Write([]byte(msg))
		return base64.StdEncoding.EncodeToString(h.Sum(nil))
	},
}

func (s *catalogSender) tmpl(src string) (*template.Template, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.cache[src]; ok {
		return t, nil
	}
	t, err := template.New("").Option("missingkey=zero").Funcs(templateFuncs).Funcs(template.FuncMap{
		"sev": func(string, string, string) string { return "" },
		"res": func(string, string) string { return "" },
	}).Parse(src)
	if err != nil {
		return nil, err
	}
	s.cache[src] = t
	return t, nil
}

// alertValues are what templates see besides the channel's fields.
func alertValues(m message) map[string]string {
	subject, text := m.render()
	ev := func(k string) string {
		if v, ok := m.Event[k]; ok && v != nil {
			return fmt.Sprint(v)
		}
		return ""
	}
	status := "firing"
	switch ev("type") {
	case "alert_resolved":
		status = "resolved"
	case "alert_reminder":
		status = "reminder"
	case "alert_escalation":
		status = "escalation"
	case "test", "verification", "":
		status = "test"
	}
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	now := time.Now()
	sev := orDefault(ev("severity"), "info")
	emoji := map[string]string{"critical": "🔴", "warning": "🟠", "info": "🔵"}[sev]
	if status == "resolved" {
		emoji = "🟢"
	}
	return map[string]string{
		"title": subject, "text": text, "summary": orDefault(ev("summary"), subject),
		"severity": sev, "status": status, "host": ev("hostname"), "rule": ev("rule_name"),
		"incident_id": ev("incident_id"), "link": ev("url"), "emoji": emoji,
		"nonce": hex.EncodeToString(nonce), "ts": strconv.FormatInt(now.Unix(), 10),
		"ts_ms": strconv.FormatInt(now.UnixMilli(), 10),
	}
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func (s *catalogSender) render(src string, vals map[string]string) (string, error) {
	t, err := s.tmpl(src)
	if err != nil {
		return "", permanent("provider %s: bad template: %v", s.def.Type, err)
	}
	sevPick := func(c, w, i string) string {
		switch vals["severity"] {
		case "critical":
			return c
		case "warning":
			return w
		}
		return i
	}
	resPick := func(f, r string) string {
		if vals["status"] == "resolved" {
			return r
		}
		return f
	}
	data := map[string]string{}
	for k, v := range vals {
		data[k] = v
	}
	// A clone per render: the functions close over this alert, and senders
	// run concurrently.
	t, err = t.Clone()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := t.Funcs(template.FuncMap{"sev": sevPick, "res": resPick}).Execute(&b, data); err != nil {
		return "", permanent("provider %s: %v", s.def.Type, err)
	}
	return b.String(), nil
}

// renderTree renders every string leaf of a JSON body.
func (s *catalogSender) renderTree(v any, vals map[string]string) (any, bool, error) {
	switch t := v.(type) {
	case string:
		kind, src := "", t
		for _, p := range []string{"int:", "bool:", "opt:", "float:", "list:"} {
			if strings.HasPrefix(t, p) {
				kind, src = p, t[len(p):]
			}
		}
		out, err := s.render(src, vals)
		if err != nil {
			return nil, false, err
		}
		switch kind {
		case "opt:":
			return out, out != "", nil
		case "list:":
			var items []any
			for _, item := range strings.Split(out, ",") {
				if item = strings.TrimSpace(item); item != "" {
					items = append(items, item)
				}
			}
			return items, len(items) > 0, nil
		case "int:":
			n, err := strconv.Atoi(strings.TrimSpace(out))
			if err != nil {
				return nil, false, nil // left out rather than sent wrong
			}
			return n, true, nil
		case "float:":
			f, err := strconv.ParseFloat(strings.TrimSpace(out), 64)
			if err != nil {
				return nil, false, nil
			}
			return f, true, nil
		case "bool:":
			return strings.TrimSpace(out) == "true", true, nil
		}
		return out, true, nil
	case map[string]any:
		m := map[string]any{}
		for k, child := range t {
			r, keep, err := s.renderTree(child, vals)
			if err != nil {
				return nil, false, err
			}
			if keep {
				m[k] = r
			}
		}
		return m, true, nil
	case []any:
		var a []any
		for _, child := range t {
			r, keep, err := s.renderTree(child, vals)
			if err != nil {
				return nil, false, err
			}
			if keep {
				a = append(a, r)
			}
		}
		return a, true, nil
	}
	return v, true, nil
}

func (s *catalogSender) sendWithConfig(ctx context.Context, target string, cfg map[string]string, m message) error {
	d := s.def
	vals := alertValues(m)
	for _, f := range d.Fields {
		v := cfg[f.Key]
		if v == "" {
			v = f.Default
		}
		if f.URL && v != "" {
			v = strings.TrimRight(v, "/")
			if err := urlAllowed(v, f.Hosts); err != nil {
				return permanent("%s %s: %v", d.Label, f.Label, err)
			}
		}
		if v == "" && f.Required {
			return permanent("%s contact is missing %s", d.Label, f.Label)
		}
		vals[f.Key] = v
	}
	rawURL, err := s.render(d.Request.URL, vals)
	if err != nil {
		return err
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return permanent("%s: invalid URL", d.Label)
	}
	var body io.Reader
	contentType := ""
	switch d.Request.Format {
	case "json":
		tree, _, err := s.renderTree(d.Request.Body, vals)
		if err != nil {
			return err
		}
		b, err := json.Marshal(tree)
		if err != nil {
			return permanent("%s: %v", d.Label, err)
		}
		body, contentType = bytes.NewReader(b), "application/json"
	case "form", "query":
		form := url.Values{}
		if mb, ok := d.Request.Body.(map[string]any); ok {
			for k, child := range mb {
				r, keep, err := s.renderTree(child, vals)
				if err != nil {
					return err
				}
				if keep {
					form.Set(k, fmt.Sprint(r))
				}
			}
		}
		if d.Request.Format == "form" {
			body, contentType = strings.NewReader(form.Encode()), "application/x-www-form-urlencoded"
		} else {
			q := u.Query()
			for k, v := range form {
				q[k] = v
			}
			u.RawQuery = q.Encode()
		}
	case "text":
		src, _ := d.Request.Body.(string)
		out, err := s.render(src, vals)
		if err != nil {
			return err
		}
		body, contentType = strings.NewReader(out), "text/plain; charset=utf-8"
	}
	req, err := http.NewRequestWithContext(ctx, orDefault(d.Request.Method, http.MethodPost), u.String(), body)
	if err != nil {
		return permanent("%s: %v", d.Label, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("User-Agent", "Sentinel/1")
	for k, src := range d.Request.Headers {
		v, err := s.render(src, vals)
		if err != nil {
			return err
		}
		if v = strings.TrimSpace(v); v != "" {
			req.Header.Set(k, v)
		}
	}
	if d.Request.OAuth != nil {
		tok, err := s.oauthToken(ctx, vals)
		if err != nil {
			return redactErr(err, vals, d)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if d.Request.BasicAuth[0] != "" {
		user, err := s.render(d.Request.BasicAuth[0], vals)
		if err != nil {
			return err
		}
		pass, err := s.render(d.Request.BasicAuth[1], vals)
		if err != nil {
			return err
		}
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return redactErr(err, vals, d)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	short := strings.TrimSpace(cut(string(raw), 300))
	short = redact(short, vals, d)
	switch {
	case resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 && resp.StatusCode != 408:
		return permanent("%s returned %s: %s", d.Label, resp.Status, short)
	case resp.StatusCode >= 300:
		return fmt.Errorf("%s returned %s: %s", d.Label, resp.Status, short)
	}
	if d.Request.OKPath != "" {
		var doc any
		if json.Unmarshal(raw, &doc) != nil {
			return fmt.Errorf("%s answered with something other than JSON: %s", d.Label, short)
		}
		got := jsonAt(doc, d.Request.OKPath)
		for _, ok := range d.Request.OKValues {
			if got == ok {
				return nil
			}
		}
		return permanent("%s refused the message: %s", d.Label, short)
	}
	return nil
}

func jsonAt(doc any, path string) string {
	cur := doc
	for _, k := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[k]
	}
	switch v := cur.(type) {
	case nil:
		return ""
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	}
	b, _ := json.Marshal(cur)
	return string(b)
}

// redact keeps secret fields out of errors, which end up on the delivery
// list in the UI.
func redact(s string, vals map[string]string, d proto.Notifier) string {
	for _, f := range d.Fields {
		if v := vals[f.Key]; f.Secret && len(v) >= 4 {
			s = strings.ReplaceAll(s, v, "****")
			s = strings.ReplaceAll(s, url.PathEscape(v), "****")
			s = strings.ReplaceAll(s, url.QueryEscape(v), "****")
		}
	}
	return s
}

func redactErr(err error, vals map[string]string, d proto.Notifier) error {
	var perm *permanentError
	msg := redact(err.Error(), vals, d)
	if errors.As(err, &perm) {
		return permanent("%s", msg)
	}
	return fmt.Errorf("%s", msg)
}

// urlAllowed: http(s), and for a service-issued webhook URL, the service's
// own host. Private addresses are refused by the client at connect time.
func urlAllowed(raw string, hosts []string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
		return errors.New("must be an http(s) URL")
	}
	if len(hosts) == 0 {
		return nil
	}
	h := strings.ToLower(u.Hostname())
	for _, a := range hosts {
		if h == strings.TrimPrefix(a, ".") || (strings.HasPrefix(a, ".") && strings.HasSuffix(h, a)) {
			if u.Scheme != "https" {
				return errors.New("must be https")
			}
			return nil
		}
	}
	return fmt.Errorf("must be on %s", strings.TrimPrefix(hosts[0], "."))
}

// oauthToken gets an access token with the client credentials grant, kept
// until a minute before it expires. A refused credential is permanent: the
// contact's settings are wrong, not the service.
func (s *catalogSender) oauthToken(ctx context.Context, vals map[string]string) (string, error) {
	o := s.def.Request.OAuth
	var parts [4]string
	for i, src := range []string{o.TokenURL, o.ClientID, o.ClientSecret, o.Scope} {
		v, err := s.render(src, vals)
		if err != nil {
			return "", err
		}
		parts[i] = v
	}
	tokenURL, id, secret, scope := parts[0], parts[1], parts[2], parts[3]
	if u, err := url.Parse(tokenURL); err != nil || u.Scheme != "https" || u.Host == "" {
		return "", permanent("%s: invalid token URL", s.def.Label)
	}
	key := tokenURL + "\x00" + id + "\x00" + scope + "\x00" + secret
	s.mu.Lock()
	if t, ok := s.tokens[key]; ok && time.Now().Before(t.expires) {
		s.mu.Unlock()
		return t.value, nil
	}
	s.mu.Unlock()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}}
	if scope != "" {
		form.Set("scope", scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", permanent("%s: %v", s.def.Label, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Sentinel/1")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
		return "", permanent("%s refused the sign-in (%s): check the app's ID, secret and permissions", s.def.Label, resp.Status)
	}
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("%s sign-in returned %s", s.def.Label, resp.Status)
	}
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if json.Unmarshal(raw, &t) != nil || t.AccessToken == "" {
		return "", fmt.Errorf("%s sign-in gave no access token", s.def.Label)
	}
	life := time.Duration(t.ExpiresIn)*time.Second - time.Minute
	if life < time.Minute {
		life = time.Minute
	}
	s.mu.Lock()
	s.tokens[key] = oauthToken{value: t.AccessToken, expires: time.Now().Add(life)}
	s.mu.Unlock()
	return t.AccessToken, nil
}
