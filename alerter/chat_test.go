package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

type recorder struct {
	mu     sync.Mutex
	paths  []string
	bodies []map[string]any
	forms  []url.Values
	status int
}

func (rec *recorder) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		rec.paths = append(rec.paths, r.URL.Path)
		b, _ := io.ReadAll(r.Body)
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				t.Errorf("bad JSON: %s", b)
			}
			rec.bodies = append(rec.bodies, m)
		} else {
			f, _ := url.ParseQuery(string(b))
			rec.forms = append(rec.forms, f)
		}
		if rec.status != 0 {
			w.WriteHeader(rec.status)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

var alertMsg = message{
	Subject: "[Sentinel] FIRING: CPU on web-1",
	Text:    "CPU usage is 97% <script>",
	Event:   map[string]any{"type": "alert_firing", "incident_id": "inc-1", "hostname": "web-1"},
}

func TestSlackTeamsDiscord(t *testing.T) {
	rec := &recorder{}
	srv := rec.server(t)
	client := newWebhookSender("", true).client
	for _, s := range []sender{&slackSender{client}, &teamsSender{client}, &discordSender{client}} {
		if err := s.send(context.Background(), srv.URL+"/hook", alertMsg); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(rec.bodies[0]["text"].(string), "*[Sentinel] FIRING: CPU on web-1*") {
		t.Errorf("slack: %v", rec.bodies[0])
	}
	att := rec.bodies[1]["attachments"].([]any)[0].(map[string]any)
	if att["contentType"] != "application/vnd.microsoft.card.adaptive" {
		t.Errorf("teams: %v", rec.bodies[1])
	}
	if !strings.HasPrefix(rec.bodies[2]["content"].(string), "**[Sentinel]") {
		t.Errorf("discord: %v", rec.bodies[2])
	}
}

func TestChatWebhooksRefusePrivateAddresses(t *testing.T) {
	rec := &recorder{}
	srv := rec.server(t)
	s := &slackSender{newWebhookSender("", false).client}
	err := s.send(context.Background(), srv.URL, alertMsg)
	var perm *permanentError
	if err == nil || !errorsAs(err, &perm) {
		t.Fatalf("want a permanent refusal for 127.0.0.1, got %v", err)
	}
}

func TestTelegram(t *testing.T) {
	rec := &recorder{}
	srv := rec.server(t)
	s := &telegramSender{client: http.DefaultClient, baseURL: srv.URL}
	if err := s.send(context.Background(), "123:ABC/-1001", alertMsg); err != nil {
		t.Fatal(err)
	}
	if rec.paths[0] != "/bot123:ABC/sendMessage" || rec.bodies[0]["chat_id"] != "-1001" {
		t.Errorf("path %s body %v", rec.paths[0], rec.bodies[0])
	}
	if !strings.Contains(rec.bodies[0]["text"].(string), "&lt;script&gt;") {
		t.Error("text must be HTML-escaped")
	}
	if err := s.send(context.Background(), "no-chat", alertMsg); err == nil {
		t.Error("a target without a chat id must fail")
	}
}

func TestPagerDuty(t *testing.T) {
	rec := &recorder{}
	srv := rec.server(t)
	s := &pagerDutySender{client: http.DefaultClient, url: srv.URL}
	ctx := context.Background()
	if err := s.send(ctx, "routingkey", alertMsg); err != nil {
		t.Fatal(err)
	}
	resolved := message{Subject: "x", Event: map[string]any{"type": "alert_resolved", "incident_id": "inc-1"}}
	if err := s.send(ctx, "routingkey", resolved); err != nil {
		t.Fatal(err)
	}
	test := message{Subject: "t", Event: map[string]any{"type": "test", "channel_id": "c1"}}
	if err := s.send(ctx, "routingkey", test); err != nil {
		t.Fatal(err)
	}
	actions := []string{}
	for _, b := range rec.bodies {
		actions = append(actions, b["event_action"].(string)+":"+b["dedup_key"].(string))
	}
	want := "trigger:inc-1,resolve:inc-1,trigger:sentinel-test-c1,resolve:sentinel-test-c1"
	if strings.Join(actions, ",") != want {
		t.Errorf("got %v", actions)
	}
	if rec.bodies[0]["payload"].(map[string]any)["source"] != "web-1" {
		t.Error("source should be the hostname")
	}
	rec.status = http.StatusBadRequest
	var perm *permanentError
	if err := s.send(ctx, "bad", alertMsg); !errorsAs(err, &perm) {
		t.Errorf("400 must be permanent, got %v", err)
	}
}

func TestVoice(t *testing.T) {
	rec := &recorder{}
	srv := rec.server(t)
	s := &voiceSender{accountSID: "AC1", authToken: "t", from: "+15550000000", client: http.DefaultClient, baseURL: srv.URL}
	if err := s.send(context.Background(), "+919876543210", message{Code: "123456"}); err != nil {
		t.Fatal(err)
	}
	if rec.paths[0] != "/2010-04-01/Accounts/AC1/Calls.json" {
		t.Errorf("path %s", rec.paths[0])
	}
	twiml := rec.forms[0].Get("Twiml")
	if !strings.Contains(twiml, "1, 2, 3, 4, 5, 6") {
		t.Errorf("code should be read digit by digit: %s", twiml)
	}
	if got := voiceTwiML(alertMsg); strings.Contains(got, "<script>") {
		t.Errorf("TwiML must be escaped: %s", got)
	}
	if err := (&voiceSender{}).send(context.Background(), "+1", alertMsg); err == nil {
		t.Error("unconfigured voice must fail")
	}
}

func TestLinks(t *testing.T) {
	if got := dashboardLink("https://c.example/monitoring?tab=servers", "i1"); got != "https://c.example/monitoring?tab=servers&section=alerts&incident=i1" {
		t.Errorf("console link: %s", got)
	}
	if got := dashboardLink("https://pg.example/", "i1"); got != "https://pg.example/incidents/i1" {
		t.Errorf("standalone link: %s", got)
	}
	tok := ackToken("secret", "0b1c")
	if !strings.HasPrefix(tok, "0b1c.") || tok != ackToken("secret", "0b1c") || tok == ackToken("other", "0b1c") {
		t.Errorf("token %s", tok)
	}
	if ackURL("", "s", "i") != "" || ackURL("https://a", "", "i") != "" {
		t.Error("no link without a base URL and a secret")
	}
	// Matches api/tests/test_escalation.py::test_ack_token_matches_alerter.
	if got := ackToken("test-ack-secret", "00000000-0000-0000-0000-000000000001"); got != ackFixture {
		t.Errorf("ack token changed: %s", got)
	}
}

// The API must produce the same token (api/tests/test_escalation.py).
const ackFixture = "00000000-0000-0000-0000-000000000001.GnitMVzz9iorKi3AI1lO4GU1"

func errorsAs(err error, target **permanentError) bool {
	for err != nil {
		if p, ok := err.(*permanentError); ok {
			*target = p
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// Alert text can quote customers' log lines: they mustn't ping a whole
// channel, and long or multi-byte text must still be accepted (a 400 from
// these services drops the alert for good).
func TestChatTextIsSafeAndFits(t *testing.T) {
	rec := &recorder{}
	srv := rec.server(t)
	client := newWebhookSender("", true).client
	m := message{
		Subject: "[Sentinel] FIRING: log pattern on web-1",
		Text:    "matched: <!channel> @everyone " + strings.Repeat("ошибка ", 2000),
		Event:   map[string]any{"type": "alert_firing", "incident_id": "inc-1"},
	}
	for _, s := range []sender{&slackSender{client}, &discordSender{client}} {
		if err := s.send(context.Background(), srv.URL+"/hook", m); err != nil {
			t.Fatal(err)
		}
	}
	tg := &telegramSender{client: client, baseURL: srv.URL}
	if err := tg.send(context.Background(), "123:abc/42", m); err != nil {
		t.Fatal(err)
	}
	slack := rec.bodies[0]["text"].(string)
	if strings.Contains(slack, "<!channel>") || !strings.Contains(slack, "&lt;!channel&gt;") {
		t.Errorf("slack mention not escaped: %.80s", slack)
	}
	discord := rec.bodies[1]
	if am, _ := discord["allowed_mentions"].(map[string]any); am == nil || len(am["parse"].([]any)) != 0 {
		t.Errorf("discord parses mentions: %v", discord["allowed_mentions"])
	}
	for i, field := range []string{"content", "text"} {
		s := rec.bodies[i+1][field].(string)
		if !utf8.ValidString(s) {
			t.Errorf("%s: invalid UTF-8 after cutting", field)
		}
		if n := utf8.RuneCountInString(s); n > 4096 || (field == "content" && n > 2000) {
			t.Errorf("%s: %d characters is over the limit", field, n)
		}
	}
}

func TestCutKeepsCharactersWhole(t *testing.T) {
	for n := range 12 {
		if got := cut("aé🚨b", n); !utf8.ValidString(got) || len(got) > n {
			t.Errorf("cut(%d) = %q", n, got)
		}
	}
}
