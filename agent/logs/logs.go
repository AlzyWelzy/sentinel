// Package logs ships new lines from the log files (and, on Linux, the
// systemd journal) that the server's administrator lists in logs.conf, so
// they can be searched from the dashboard.
//
// Shipping is opt-in on the server and never configured from the dashboard:
// logs can hold anything, so nothing leaves the machine unless root says so.
// logs.conf must not be writable by the agent's own user.
//
//	# <config dir>/logs.conf
//	file = /var/log/nginx/*.log
//	file = /var/log/app/app.log
//	journal = true
//
// A file seen for the first time is shipped from its end (no backfill).
// Offsets advance only after ingest has accepted the lines, and are kept in
// the state directory, so a restart neither loses nor repeats lines.
package logs

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/example-org/pulsegrid/agent/plugins"
	"github.com/example-org/pulsegrid/proto"
)

const (
	// ConfigFile is the file name in the agent's config directory.
	ConfigFile = "logs.conf"
	stateFile  = "logs-state.json"
	maxFiles   = 200
	maxLine    = 4096
	// Per file per round, so one busy file can't starve the rest.
	maxReadBytes = 4 << 20
)

// Config is what logs.conf asks for.
type Config struct {
	Files   []string // glob patterns
	Dirs    []string // every readable text log under these, recursively
	Journal bool
	Docker  bool // what running containers print
}

// LoadConfig reads logs.conf. A missing file means shipping is off.
func LoadConfig(dir string) (Config, bool, error) {
	path := filepath.Join(dir, ConfigFile)
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, false, nil
	}
	if err != nil {
		return Config{}, false, err
	}
	defer f.Close()
	if err := plugins.CheckOwnership(path); err != nil {
		return Config{}, false, err
	}
	var c Config
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return Config{}, false, fmt.Errorf("%s line %d: expected key = value", ConfigFile, n)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "file":
			if !filepath.IsAbs(v) {
				return Config{}, false, fmt.Errorf("%s line %d: %q isn't an absolute path", ConfigFile, n, v)
			}
			if _, err := filepath.Match(v, ""); err != nil {
				return Config{}, false, fmt.Errorf("%s line %d: bad pattern %q", ConfigFile, n, v)
			}
			c.Files = append(c.Files, v)
		case "dir":
			if !filepath.IsAbs(v) {
				return Config{}, false, fmt.Errorf("%s line %d: %q isn't an absolute path", ConfigFile, n, v)
			}
			c.Dirs = append(c.Dirs, v)
		case "docker":
			c.Docker = v == "true" || v == "yes" || v == "1"
		case "journal":
			c.Journal = v == "true" || v == "yes" || v == "1"
		default:
			return Config{}, false, fmt.Errorf("%s line %d: unknown key %q", ConfigFile, n, k)
		}
	}
	if err := sc.Err(); err != nil {
		return Config{}, false, err
	}
	return c, true, nil
}

type fileState struct {
	Offset int64  `json:"offset"`
	ID     uint64 `json:"id"`
}

type savedState struct {
	Files         map[string]fileState `json:"files"`
	JournalCursor string               `json:"journal_cursor,omitempty"`
	Docker        map[string]int64     `json:"docker,omitempty"`
}

// Shipper remembers where each source was read up to.
type Shipper struct {
	stateDir string
	st       savedState
	pending  savedState
	now      func() time.Time
	round    int
}

// NewShipper loads the saved offsets from stateDir.
func NewShipper(stateDir string) *Shipper {
	s := &Shipper{stateDir: stateDir, now: time.Now}
	if b, err := os.ReadFile(filepath.Join(stateDir, stateFile)); err == nil {
		json.Unmarshal(b, &s.st)
	}
	if s.st.Files == nil {
		s.st.Files = map[string]fileState{}
	}
	return s
}

// Collect reads up to max new lines. Nothing is marked as read until Commit.
// It returns notes about sources that couldn't be read (shown in inventory).
func (s *Shipper) Collect(c Config, max int) ([]proto.LogEntry, []string) {
	s.pending = savedState{Files: map[string]fileState{}, JournalCursor: s.st.JournalCursor, Docker: s.st.Docker}
	var out []proto.LogEntry
	var problems []string
	paths, globErrs := expand(c.Files, walkDirs(c.Dirs, c.Journal))
	problems = append(problems, globErrs...)
	// Start somewhere new each round so busy files early in the list can't
	// starve the rest; files not reached keep their place for next time.
	if len(paths) > 0 {
		k := s.round % len(paths)
		paths = append(paths[k:], paths[:k]...)
	}
	s.round++
	for _, path := range paths {
		if len(out) >= max {
			if st, ok := s.st.Files[path]; ok {
				s.pending.Files[path] = st
			}
			continue
		}
		entries, st, err := s.readFile(path, s.st.Files[path], max-len(out))
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		s.pending.Files[path] = st
		out = append(out, entries...)
	}
	if c.Journal && len(out) < max {
		entries, cursor, err := readJournal(s.st.JournalCursor, max-len(out))
		if err != nil {
			problems = append(problems, "journal: "+err.Error())
		} else {
			s.pending.JournalCursor = cursor
			out = append(out, entries...)
		}
	}
	if c.Docker {
		entries, since, err := readDocker(s.st.Docker, max-len(out), s.now())
		if err != nil {
			problems = append(problems, "docker: "+err.Error())
		} else {
			s.pending.Docker = since
			out = append(out, entries...)
		}
	}
	return out, problems
}

// Commit marks what the last Collect returned as shipped.
func (s *Shipper) Commit() {
	for path, st := range s.pending.Files {
		s.st.Files[path] = st
	}
	// Forget files that no longer match, so the state doesn't grow forever.
	for path := range s.st.Files {
		if _, ok := s.pending.Files[path]; !ok {
			delete(s.st.Files, path)
		}
	}
	s.st.JournalCursor = s.pending.JournalCursor
	s.st.Docker = s.pending.Docker
	if b, err := json.Marshal(s.st); err == nil {
		tmp := filepath.Join(s.stateDir, stateFile+".tmp")
		if os.WriteFile(tmp, b, 0o600) == nil {
			os.Rename(tmp, filepath.Join(s.stateDir, stateFile))
		}
	}
}

func expand(patterns, found []string) ([]string, []string) {
	seen := map[string]bool{}
	var out, problems []string
	for _, m := range found {
		seen[m] = true
		out = append(out, m)
	}
	for _, p := range patterns {
		matches, _ := filepath.Glob(p)
		if len(matches) == 0 {
			problems = append(problems, p+": no such file")
		}
		for _, m := range matches {
			if fi, err := os.Stat(m); err == nil && fi.Mode().IsRegular() && !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	sort.Strings(out)
	if len(out) > maxFiles {
		problems = append(problems, fmt.Sprintf("only the first %d files are shipped", maxFiles))
		out = out[:maxFiles]
	}
	return out, problems
}

// Copies of the journal that rsyslog writes; shipping them too would double
// every line.
var journalCopies = map[string]bool{
	"syslog": true, "messages": true, "auth.log": true, "secure": true, "kern.log": true,
	"daemon.log": true, "user.log": true, "debug": true, "mail.log": true, "cron.log": true,
}

// Binary files and the journal's own store, which aren't lines of text.
var notText = map[string]bool{"wtmp": true, "btmp": true, "lastlog": true, "faillog": true, "journal": true, "private": true}

// rotated matches log.1, log.2.gz, log-20261031, log.old and other copies
// logrotate leaves behind: their lines were shipped while they were live.
var rotated = regexp.MustCompile(`(\.\d+|[-.]\d{8}|\.old|\.gz|\.xz|\.bz2|\.zst|\.zip)(\.gz)?$`)

// walkDirs lists the readable text logs under dirs.
func walkDirs(dirs []string, journal bool) []string {
	var out []string
	for _, d := range dirs {
		filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			name := e.Name()
			if e.IsDir() {
				if p != d && notText[name] {
					return filepath.SkipDir
				}
				return nil
			}
			if !e.Type().IsRegular() || notText[name] || rotated.MatchString(name) ||
				(journal && filepath.Dir(p) == filepath.Clean(d) && journalCopies[name]) {
				return nil
			}
			if isText(p) {
				out = append(out, p)
			}
			return nil
		})
	}
	return out
}

// isText: readable by us, and no NUL byte in its first 512 bytes.
func isText(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	b := make([]byte, 512)
	n, _ := f.Read(b)
	return !bytes.Contains(b[:n], []byte{0})
}

func (s *Shipper) readFile(path string, prev fileState, max int) ([]proto.LogEntry, fileState, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, prev, fmt.Errorf("%s: permission denied (add the agent's user to the file's group)", path)
		}
		return nil, prev, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, prev, err
	}
	id := fileID(fi)
	if _, known := s.st.Files[path]; !known {
		// New to us: start at the end.
		return nil, fileState{Offset: fi.Size(), ID: id}, nil
	}
	if id != prev.ID || fi.Size() < prev.Offset {
		prev = fileState{Offset: 0, ID: id} // rotated or truncated
	}
	if _, err := f.Seek(prev.Offset, io.SeekStart); err != nil {
		return nil, prev, err
	}
	r := bufio.NewReaderSize(io.LimitReader(f, maxReadBytes), 64<<10)
	var out []proto.LogEntry
	offset := prev.Offset
	source := path
	now := s.now().UnixNano()
	for len(out) < max {
		line, err := r.ReadString('\n')
		if err == io.EOF && !strings.HasSuffix(line, "\n") {
			break // partial last line: next round
		}
		offset += int64(len(line))
		line = strings.TrimRight(line, "\r\n")
		if line != "" {
			out = append(out, proto.LogEntry{TimestampNs: now, Source: source, Level: DetectLevel(line), Line: clip(line)})
		}
		if err != nil {
			break
		}
	}
	return out, fileState{Offset: offset, ID: id}, nil
}

func clip(s string) string {
	if len(s) <= maxLine {
		return s
	}
	return s[:maxLine] + "…"
}

var levelRE = regexp.MustCompile(`(?i)\b(emerg|emergency|alert|crit|critical|fatal|panic|err|error|warn|warning|notice|info|debug|trace)\b`)

// DetectLevel finds the first level word in a line: error, warning, info or
// debug, or "" when there isn't one.
func DetectLevel(line string) string {
	head := line
	if len(head) > 200 {
		head = head[:200]
	}
	m := levelRE.FindString(head)
	switch strings.ToLower(m) {
	case "emerg", "emergency", "alert", "crit", "critical", "fatal", "panic", "err", "error":
		return "error"
	case "warn", "warning":
		return "warning"
	case "notice", "info":
		return "info"
	case "debug", "trace":
		return "debug"
	}
	return ""
}

// journalLevel maps syslog priorities (0 emerg … 7 debug).
func journalLevel(p string) string {
	switch p {
	case "0", "1", "2", "3":
		return "error"
	case "4":
		return "warning"
	case "5", "6":
		return "info"
	case "7":
		return "debug"
	}
	return ""
}
