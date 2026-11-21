package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"text/template"

	"github.com/AlzyWelzy/sentinel/proto"
)

// catalogRecorder answers every request the way the provider's success looks.
type catalogRecorder struct {
	mu   sync.Mutex
	reqs []*http.Request
	body []string
	ok   string
}

func (r *catalogRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	b := ""
	if req.Body != nil {
		raw, _ := io.ReadAll(req.Body)
		b = string(raw)
	}
	r.mu.Lock()
	r.reqs = append(r.reqs, req)
	r.body = append(r.body, b)
	r.mu.Unlock()
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(r.ok)), Header: http.Header{}}, nil
}

// okBody builds {"a":{"b":v}} for ok_path a.b.
func okBody(path, v string) string {
	if path == "" {
		return `{}`
	}
	var val any = v
	if v == "true" || v == "false" {
		val = v == "true"
	} else if n, err := json.Number(v).Float64(); err == nil {
		val = n
	}
	parts := strings.Split(path, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		val = map[string]any{parts[i]: val}
	}
	b, _ := json.Marshal(val)
	return string(b)
}

func sampleValue(f proto.NotifierField) string {
	switch {
	case len(f.Options) > 0:
		return f.Options[0][0]
	case len(f.Hosts) > 0:
		return "https://" + strings.TrimPrefix(f.Hosts[0], ".") + "/hook/abcdef123456"
	case f.URL:
		return "https://notify.example.com/base"
	}
	samples := map[string]string{
		`^\+?[0-9 ,]{6,200}$`:   "+15551234567",
		`^[0-9]+$`:              "12345",
		`^-?[0-9]+$`:            "2000000001",
		`^\*[A-Z0-9]{7}$`:       "*SENTINL",
		`^[A-Z0-9*]{8}$`:        "ECHOECHO",
		`^AC[0-9a-f]{32}$`:      "AC" + strings.Repeat("0", 32),
		`^![^:]+:.+$`:           "!room:matrix.org",
		`^[A-Za-z0-9_-]{1,64}$`: "alerts",
	}
	if v, ok := samples[f.Pattern]; ok {
		return v
	}
	if f.Pattern != "" {
		panic("no sample for pattern " + f.Pattern)
	}
	if f.Secret {
		return "s3cr3t-" + f.Key + "-value"
	}
	return "value-" + f.Key
}

func TestEveryCatalogProviderSends(t *testing.T) {
	defs, err := proto.Notifiers()
	if err != nil {
		t.Fatal(err)
	}
	if len(defs) < 90 {
		t.Fatalf("only %d providers", len(defs))
	}
	builtin := senders(&emailSender{})
	for _, d := range defs {
		t.Run(d.Type, func(t *testing.T) {
			if _, ok := builtin[d.Type].(*catalogSender); !ok {
				t.Fatalf("%s isn't registered as a catalog sender (a built-in sender has the name?)", d.Type)
			}
			cfg := map[string]string{}
			for _, f := range d.Fields {
				if f.Pattern != "" {
					if _, err := regexp.Compile(f.Pattern); err != nil {
						t.Fatalf("field %s pattern: %v", f.Key, err)
					}
				}
				cfg[f.Key] = sampleValue(f)
			}
			ok := ""
			if len(d.Request.OKValues) > 0 {
				ok = d.Request.OKValues[0]
			}
			rec := &catalogRecorder{ok: okBody(d.Request.OKPath, ok)}
			s := &catalogSender{def: d, client: &http.Client{Transport: rec}, cache: map[string]*template.Template{}}
			for _, kind := range []string{"alert_firing", "alert_resolved"} {
				m := message{Subject: "[Sentinel] CRITICAL: db-1 disk full", Text: "Disk / is 97% full\nHost: db-1",
					Event: map[string]any{"type": kind, "severity": "critical", "summary": "db-1 disk full",
						"hostname": "db-1", "rule_name": "Disk", "incident_id": "6f1c2b9e-1111-4222-8333-444455556666",
						"url": "https://sentinel.example.com/incidents/6f1c"}}
				if err := s.sendWithConfig(context.Background(), "", cfg, m); err != nil {
					t.Fatalf("%s: %v", kind, err)
				}
			}
			if len(rec.reqs) != 2 {
				t.Fatalf("%d requests", len(rec.reqs))
			}
			for i, req := range rec.reqs {
				all := req.URL.String() + " " + rec.body[i]
				for k, v := range req.Header {
					all += " " + k + ": " + strings.Join(v, ",")
				}
				if strings.Contains(all, "<no value>") || strings.Contains(all, "{{") {
					t.Fatalf("unrendered template: %s", all)
				}
				if req.URL.Scheme != "https" {
					t.Fatalf("not https: %s", req.URL)
				}
				ct := req.Header.Get("Content-Type")
				if strings.HasPrefix(ct, "application/json") && !json.Valid([]byte(rec.body[i])) {
					t.Fatalf("invalid JSON: %s", rec.body[i])
				}
				if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
					if _, err := url.ParseQuery(rec.body[i]); err != nil {
						t.Fatalf("bad form: %v", err)
					}
				}
				if !strings.Contains(all, "disk") && !strings.Contains(all, "Disk") {
					t.Fatalf("the alert isn't in the request: %s", all)
				}
			}
		})
	}
}

func TestCatalogRefusesOffServiceWebhookAndRedactsSecrets(t *testing.T) {
	defs, _ := proto.Notifiers()
	var gc proto.Notifier
	for _, d := range defs {
		if d.Type == "google_chat" {
			gc = d
		}
	}
	rec := &catalogRecorder{ok: "{}"}
	s := &catalogSender{def: gc, client: &http.Client{Transport: rec}, cache: map[string]*template.Template{}}
	err := s.sendWithConfig(context.Background(), "", map[string]string{"webhook_url": "https://evil.example.com/x"}, message{Subject: "x"})
	if err == nil || !strings.Contains(err.Error(), "chat.googleapis.com") || len(rec.reqs) != 0 {
		t.Fatalf("off-service URL: %v, %d requests", err, len(rec.reqs))
	}
	// A refusal that echoes the key back doesn't put it in the delivery list.
	var po proto.Notifier
	for _, d := range defs {
		if d.Type == "pushover" {
			po = d
		}
	}
	bad := &catalogRecorder{ok: `{"status":0,"errors":["application token is invalid: tok-SECRET-123"]}`}
	s = &catalogSender{def: po, client: &http.Client{Transport: bad}, cache: map[string]*template.Template{}}
	err = s.sendWithConfig(context.Background(), "", map[string]string{"user_key": "u-1234", "app_token": "tok-SECRET-123"}, message{Subject: "x"})
	if err == nil || strings.Contains(err.Error(), "tok-SECRET-123") {
		t.Fatalf("got %v", err)
	}
	var perm *permanentError
	if !errorsAs(err, &perm) {
		t.Fatalf("a refused message should be permanent: %v", err)
	}
}

func sendOne(t *testing.T, typ string, cfg map[string]string, kind, okBody string) (*http.Request, string) {
	t.Helper()
	defs, _ := proto.Notifiers()
	for _, d := range defs {
		if d.Type != typ {
			continue
		}
		rec := &catalogRecorder{ok: okBody}
		s := &catalogSender{def: d, client: &http.Client{Transport: rec}, cache: map[string]*template.Template{}}
		m := message{Subject: "db-1 down", Text: "not reporting", Event: map[string]any{
			"type": kind, "severity": "critical", "summary": "db-1 down", "incident_id": "inc-1"}}
		if err := s.sendWithConfig(context.Background(), "", cfg, m); err != nil {
			t.Fatal(err)
		}
		return rec.reqs[0], rec.body[0]
	}
	t.Fatalf("no provider %s", typ)
	return nil, ""
}

func TestCatalogDetails(t *testing.T) {
	req, body := sendOne(t, "opsgenie", map[string]string{"api_key": "k", "region": "eu"}, "alert_firing", "{}")
	if req.URL.String() != "https://api.eu.opsgenie.com/v2/alerts" || !strings.Contains(body, `"priority":"P1"`) ||
		req.Header.Get("Authorization") != "GenieKey k" || strings.Contains(body, `"note"`) {
		t.Fatalf("opsgenie firing: %s %s", req.URL, body)
	}
	req, body = sendOne(t, "opsgenie", map[string]string{"api_key": "k", "region": "us"}, "alert_resolved", "{}")
	if req.URL.String() != "https://api.opsgenie.com/v2/alerts/inc-1/close?identifierType=alias" || !strings.Contains(body, `"note":"not reporting"`) {
		t.Fatalf("opsgenie resolved: %s %s", req.URL, body)
	}
	req, body = sendOne(t, "ntfy", map[string]string{"topic": "ops"}, "alert_firing", "{}")
	if req.URL.String() != "https://ntfy.sh/ops" || req.Header.Get("Priority") != "5" || req.Header.Get("Title") != "db-1 down" ||
		body != "not reporting" || req.Header.Get("Authorization") != "" {
		t.Fatalf("ntfy: %s %v %q", req.URL, req.Header, body)
	}
	if _, _, ok := req.BasicAuth(); ok {
		t.Fatal("ntfy without credentials sent basic auth")
	}
	req, _ = sendOne(t, "ntfy", map[string]string{"topic": "ops", "token": "tk_1"}, "alert_resolved", "{}")
	if req.Header.Get("Authorization") != "Bearer tk_1" || req.Header.Get("Tags") != "white_check_mark" {
		t.Fatalf("ntfy token: %v", req.Header)
	}
	req, _ = sendOne(t, "dingtalk", map[string]string{"webhook_url": "https://oapi.dingtalk.com/robot/send?access_token=x", "secret": "SEC1"}, "alert_firing", `{"errcode":0}`)
	q := req.URL.Query()
	if q.Get("timestamp") == "" || q.Get("sign") == "" || q.Get("access_token") != "x" {
		t.Fatalf("dingtalk: %s", req.URL)
	}
	req, _ = sendOne(t, "serverchan", map[string]string{"send_key": "sctp1234tABCDEF"}, "alert_firing", `{"code":0}`)
	if req.URL.Host != "1234.push.ft07.com" {
		t.Fatalf("serverchan sctp: %s", req.URL)
	}
	req, _ = sendOne(t, "serverchan", map[string]string{"send_key": "SCT9999"}, "alert_firing", `{"code":0}`)
	if req.URL.String() != "https://sctapi.ftqq.com/SCT9999.send" {
		t.Fatalf("serverchan: %s", req.URL)
	}
	_, body = sendOne(t, "gotify", map[string]string{"server": "https://push.example.com", "app_token": "t"}, "alert_firing", "{}")
	if !strings.Contains(body, `"priority":8`) {
		t.Fatalf("gotify priority isn't a number: %s", body)
	}
	_, body = sendOne(t, "signal", map[string]string{"server": "https://signal.example.com", "number": "+1555", "recipients": "+1666, +1777"}, "alert_firing", "{}")
	if !strings.Contains(body, `"recipients":["+1666","+1777"]`) {
		t.Fatalf("signal recipients: %s", body)
	}
	_, body = sendOne(t, "onebot", map[string]string{"server": "https://qq.example.com", "kind": "group", "to": "42"}, "alert_firing", "{}")
	if !strings.Contains(body, `"group_id":"42"`) || strings.Contains(body, "user_id") {
		t.Fatalf("onebot group: %s", body)
	}
}
