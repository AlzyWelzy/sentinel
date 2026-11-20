package logs

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/AlzyWelzy/sentinel/agent/plugins"
)

func appendTo(t *testing.T, path, s string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(s)
	f.Close()
}

func TestConfig(t *testing.T) {
	plugins.AllowUserOwnedForTests()
	dir := t.TempDir()
	if _, on, err := LoadConfig(dir); on || err != nil {
		t.Fatalf("missing file should mean off: %v %v", on, err)
	}
	abs := filepath.Join(dir, "*.log")
	os.WriteFile(filepath.Join(dir, ConfigFile), []byte("# app\nfile = "+abs+"\njournal = true\n"), 0o644)
	c, on, err := LoadConfig(dir)
	if err != nil || !on || len(c.Files) != 1 || c.Files[0] != abs || !c.Journal {
		t.Fatalf("%+v %v %v", c, on, err)
	}
	for _, bad := range []string{"file = relative.log\n", "colour = blue\n", "nonsense\n"} {
		os.WriteFile(filepath.Join(dir, ConfigFile), []byte(bad), 0o644)
		if _, _, err := LoadConfig(dir); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if runtime.GOOS != "windows" {
		os.WriteFile(filepath.Join(dir, ConfigFile), []byte("journal = true\n"), 0o666)
		os.Chmod(filepath.Join(dir, ConfigFile), 0o666)
		if _, _, err := LoadConfig(dir); err == nil {
			t.Fatal("world-writable logs.conf must be refused")
		}
	}
}

func TestShipping(t *testing.T) {
	dir, state := t.TempDir(), t.TempDir()
	log := filepath.Join(dir, "app.log")
	appendTo(t, log, "old line before we started\n")
	cfg := Config{Files: []string{filepath.Join(dir, "*.log")}}

	s := NewShipper(state)
	if got, _ := s.Collect(cfg, 100); len(got) != 0 {
		t.Fatalf("first sight must not backfill: %+v", got)
	}
	s.Commit()
	appendTo(t, log, "INFO started\nERROR db down\npartial")
	got, _ := s.Collect(cfg, 100)
	if len(got) != 2 || got[0].Line != "INFO started" || got[0].Level != "info" || got[1].Level != "error" || got[1].Source != log {
		t.Fatalf("%+v", got)
	}
	// Not committed (push failed): the same lines come again.
	if again, _ := s.Collect(cfg, 100); len(again) != 2 {
		t.Fatalf("uncommitted lines must be resent: %+v", again)
	}
	s.Commit()
	if none, _ := s.Collect(cfg, 100); len(none) != 0 {
		t.Fatalf("%+v", none)
	}
	s.Commit()

	// A restart picks up where it left off; the partial line completes.
	s = NewShipper(state)
	appendTo(t, log, " line\nWARN slow\n")
	got, _ = s.Collect(cfg, 1)
	if len(got) != 1 || got[0].Line != "partial line" {
		t.Fatalf("max and resume: %+v", got)
	}
	s.Commit()
	got, _ = s.Collect(cfg, 10)
	if len(got) != 1 || got[0].Level != "warning" {
		t.Fatalf("%+v", got)
	}
	s.Commit()

	// Rotation: a new, shorter file is read from the start.
	os.Remove(log)
	appendTo(t, log, "fresh\n")
	got, _ = s.Collect(cfg, 10)
	if len(got) != 1 || got[0].Line != "fresh" {
		t.Fatalf("rotation: %+v", got)
	}

	if _, problems := s.Collect(Config{Files: []string{"/nope/*.log"}}, 10); len(problems) != 1 {
		t.Fatalf("missing files should be reported: %v", problems)
	}
}

func TestDetectLevel(t *testing.T) {
	for line, want := range map[string]string{
		"2026-10-25 [error] upstream timed out": "error",
		"Oct 25 kernel: CRITICAL temperature":   "error",
		"level=warn msg=slow":                   "warning",
		`{"level":"info","msg":"ok"}`:           "info",
		"GET /index.html 200":                   "",
		"terrorist is not a level":              "",
		"DEBUG cache miss":                      "debug",
	} {
		if got := DetectLevel(line); got != want {
			t.Errorf("%q: got %q want %q", line, got, want)
		}
	}
	if journalLevel("3") != "error" || journalLevel("6") != "info" {
		t.Fatal("journal priorities")
	}
}

func TestWalkDirsSkipsCopiesBinaryAndJournalDuplicates(t *testing.T) {
	d := t.TempDir()
	w := func(p, body string) {
		os.MkdirAll(filepath.Dir(filepath.Join(d, p)), 0o755)
		os.WriteFile(filepath.Join(d, p), []byte(body), 0o644)
	}
	w("nginx/access.log", "GET /\n")
	w("nginx/access.log.1", "old\n")
	w("nginx/error.log.2.gz", "x")
	w("dpkg.log", "install\n")
	w("syslog", "dup\n")
	w("app/syslog", "nested is kept\n")
	w("wtmp", "x")
	w("bin.dat", "a\x00b")
	w("apt/history.log-20261031", "old\n")
	w("journal/abc/system.journal", "x")
	got := walkDirs([]string{d}, true)
	for i := range got {
		r, _ := filepath.Rel(d, got[i])
		got[i] = filepath.ToSlash(r)
	}
	sort.Strings(got)
	want := []string{"app/syslog", "dpkg.log", "nginx/access.log"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := walkDirs([]string{d}, false); len(got) != 4 {
		t.Fatalf("without the journal syslog should ship too: %v", got)
	}
}

func TestParseDockerLogsFramedAndPlain(t *testing.T) {
	frame := func(s string) []byte {
		b := []byte{1, 0, 0, 0, 0, 0, 0, byte(len(s))}
		return append(b, s...)
	}
	in := append(frame("2026-10-31T10:00:00Z old\n"), frame("2026-10-31T10:00:02.5Z ERROR boom\n")...)
	after := mustNs(t, "2026-10-31T10:00:01Z")
	got, newest := parseDockerLogs(bytes.NewReader(in), "docker:web", after, 10)
	if len(got) != 1 || got[0].Line != "ERROR boom" || got[0].Level != "error" || newest != mustNs(t, "2026-10-31T10:00:02.5Z") {
		t.Fatalf("framed: %+v %d", got, newest)
	}
	got, _ = parseDockerLogs(strings.NewReader("2026-10-31T10:00:03Z hello\n"), "docker:tty", after, 10)
	if len(got) != 1 || got[0].Line != "hello" {
		t.Fatalf("plain: %+v", got)
	}
}

func mustNs(t *testing.T, s string) int64 {
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return v.UnixNano()
}

func TestExpandKeepsRecentFilesOverCap(t *testing.T) {
	d := t.TempDir()
	var found []string
	old := time.Now().Add(-48 * time.Hour)
	for i := 0; i < maxFiles+20; i++ {
		p := filepath.Join(d, fmt.Sprintf("a%03d.log", i))
		os.WriteFile(p, []byte("x\n"), 0o644)
		os.Chtimes(p, old, old)
		found = append(found, p)
	}
	live := filepath.Join(d, "zzz-live.log")
	os.WriteFile(live, []byte("x\n"), 0o644)
	found = append(found, live)
	got, problems := expand(nil, found)
	if len(got) != maxFiles || len(problems) != 1 {
		t.Fatalf("got %d files, problems %v", len(got), problems)
	}
	if !slices.Contains(got, live) {
		t.Fatal("the recently written file was dropped")
	}
}
