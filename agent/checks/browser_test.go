package checks

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AlzyWelzy/sentinel/proto"
)

func TestParseSteps(t *testing.T) {
	ok := `[{"action":"type","selector":"#u","text":"{{username}}"},{"action":"click","selector":"button"},
		{"action":"wait","selector":".dash"},{"action":"expect_text","text":"Hi"},{"action":"sleep","ms":100},
		{"action":"goto","url":"https://example.com/x"}]`
	if s, err := parseSteps(ok); err != nil || len(s) != 6 {
		t.Fatal(s, err)
	}
	for _, bad := range []string{`{}`, `[{"action":"click"}]`, `[{"action":"goto","url":"file:///etc/passwd"}]`,
		`[{"action":"sleep","ms":99999}]`, `[{"action":"eval","text":"x"}]`, `[{"action":"expect_text"}]`} {
		if _, err := parseSteps(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if got := typedText(browserStep{Text: "{{username}}:{{password}}"}, map[string]string{"username": "u", "password": "p"}); got != "u:p" {
		t.Fatal(got)
	}
}

const loginPage = `<!doctype html><html><body>
<form id="f"><input id="user"><input id="pw" type="password"><button id="go" type="button">Sign in</button></form>
<div id="out"></div>
<script>
document.getElementById("go").onclick = () => {
  const ok = document.getElementById("user").value === "ada" && document.getElementById("pw").value === "s3cret";
  setTimeout(() => { document.getElementById("out").innerHTML = ok ? '<p class="dash">Welcome, Ada</p>' : "Wrong password"; }, 300);
};
</script></body></html>`

func browserServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(loginPage))
		case "/broken":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body>Shop<script>undefinedFunction()</script><img src="/missing.png"></body></html>`))
		case "/down":
			http.Error(w, "maintenance", 503)
		default:
			http.NotFound(w, r)
		}
	}))
}

func needChromium(t *testing.T) {
	if findChromium() == "" {
		t.Skip("no Chromium here (set SENTINEL_CHROME)")
	}
}

func TestBrowserLogin(t *testing.T) {
	needChromium(t)
	srv := browserServer()
	defer srv.Close()
	r := NewRunner("test")
	steps := `[{"action":"type","selector":"#user","text":"{{username}}"},
		{"action":"type","selector":"#pw","text":"{{password}}"},
		{"action":"click","selector":"#go"},
		{"action":"wait","selector":".dash"},
		{"action":"expect_text","text":"Welcome, Ada"}]`
	c := proto.Check{ID: "b1", Type: "browser", Target: srv.URL + "/", Params: map[string]string{
		"steps": steps, "username": "ada", "password": "s3cret", "timeout_seconds": "30"}}
	res := runOne(t, r, c)
	if !res.OK || !strings.Contains(res.Detail, "5 steps passed") {
		t.Fatalf("login: %+v", res)
	}
	// The wrong password: the dashboard never shows; a screenshot comes back.
	c.ID, c.Params["password"] = "b2", "nope"
	c.Params["steps"] = strings.Replace(steps, `{"action":"wait","selector":".dash"},`, "", 1)
	res = runOne(t, r, c)
	if res.OK || !strings.Contains(res.Detail, `step 4 (expect_text "Welcome, Ada")`) {
		t.Fatalf("wrong password: %+v", res)
	}
	if len(res.Screenshot) < 1000 || !bytes.HasPrefix(res.Screenshot, []byte{0xff, 0xd8}) {
		t.Fatalf("expected a JPEG screenshot, got %d bytes", len(res.Screenshot))
	}
	if strings.Contains(res.Detail, "nope") {
		t.Fatal("the password leaked into the detail")
	}
}

func TestBrowserPageProblems(t *testing.T) {
	needChromium(t)
	srv := browserServer()
	defer srv.Close()
	r := NewRunner("test")
	res := runOne(t, r, proto.Check{ID: "d", Type: "browser", Target: srv.URL + "/down"})
	if res.OK || !strings.Contains(res.Detail, "HTTP 503") {
		t.Fatalf("503: %+v", res)
	}
	res = runOne(t, r, proto.Check{ID: "e", Type: "browser", Target: srv.URL + "/broken",
		Params: map[string]string{"max_console_errors": "0"}})
	if res.OK || !strings.Contains(res.Detail, "script errors") || !strings.Contains(res.Detail, "undefinedFunction") {
		t.Fatalf("script error: %+v", res)
	}
	res = runOne(t, r, proto.Check{ID: "f", Type: "browser", Target: srv.URL + "/broken", Params: map[string]string{"keyword": "Shop"}})
	if !res.OK {
		t.Fatalf("errors allowed by default: %+v", res)
	}
	res = runOne(t, r, proto.Check{ID: "g", Type: "browser", Target: "http://name.invalid/"})
	if res.OK || !strings.Contains(res.Detail, "ERR_NAME_NOT_RESOLVED") {
		t.Fatalf("bad name: %+v", res)
	}
}

func TestBrowserPublicOnly(t *testing.T) {
	needChromium(t)
	srv := browserServer()
	defer srv.Close()
	r := NewRunner("test")
	// From a public probe, a page on loopback is refused by the guard proxy.
	res := runOne(t, r, proto.Check{ID: "p", Type: "browser", Target: srv.URL + "/",
		Params: map[string]string{"public_only": "true"}})
	if res.OK {
		t.Fatalf("a probe reached loopback: %+v", res)
	}
	res = runOne(t, r, proto.Check{ID: "q", Type: "browser", Target: srv.URL + "/",
		Params: map[string]string{"public_only": "true", "browser_ws": "ws://127.0.0.1:9222"}})
	if res.OK || !strings.Contains(res.Detail, "remote browser") {
		t.Fatalf("remote browser on a probe: %+v", res)
	}
}

// Where Chromium's sandbox can't start (Ubuntu 24.04's AppArmor, many
// containers), the check retries without it and keeps doing so.
func TestBrowserWithoutSandbox(t *testing.T) {
	needChromium(t)
	real := findChromium()
	wrapper := filepath.Join(t.TempDir(), "chromium")
	script := "#!/bin/sh\ncase \"$*\" in *--no-sandbox*) exec \"" + real + "\" \"$@\" ;; esac\necho 'No usable sandbox!' >&2\nexit 1\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SENTINEL_CHROME", wrapper)
	noSandbox.Store(false)
	t.Cleanup(func() { noSandbox.Store(false) })
	srv := browserServer()
	defer srv.Close()
	r := NewRunner("test")
	res := runOne(t, r, proto.Check{ID: "s", Type: "browser", Target: srv.URL + "/", Params: map[string]string{"keyword": "Sign in"}})
	if !res.OK || !noSandbox.Load() {
		t.Fatalf("no fallback: %+v", res)
	}
}
