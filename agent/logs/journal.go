package logs

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strconv"
	"time"

	"github.com/AlzyWelzy/sentinel/proto"
)

type journalEntry struct {
	Cursor     string          `json:"__CURSOR"`
	RealtimeUs string          `json:"__REALTIME_TIMESTAMP"`
	Message    json.RawMessage `json:"MESSAGE"`
	Priority   string          `json:"PRIORITY"`
	Identifier string          `json:"SYSLOG_IDENTIFIER"`
	Unit       string          `json:"_SYSTEMD_UNIT"`
}

// readJournal returns up to max entries after cursor. With no cursor yet it
// only finds the current end, so enabling the journal doesn't ship history.
func readJournal(cursor string, max int) ([]proto.LogEntry, string, error) {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil, cursor, errors.New("journalctl not found (the journal is Linux/systemd only)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	args := []string{"-o", "json", "--no-pager", "-q"}
	if cursor == "" {
		args = append(args, "-n", "1")
	} else {
		args = append(args, "--after-cursor", cursor)
	}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, cursor, err
	}
	if err := cmd.Start(); err != nil {
		return nil, cursor, err
	}
	defer func() {
		cancel() // stop journalctl if we left early
		cmd.Wait()
	}()
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var entries []proto.LogEntry
	next := cursor
	first := cursor == ""
	for sc.Scan() {
		var e journalEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Cursor == "" {
			continue
		}
		next = e.Cursor
		if first {
			continue
		}
		msg := journalMessage(e.Message)
		if msg == "" {
			continue
		}
		us, _ := strconv.ParseInt(e.RealtimeUs, 10, 64)
		source := "journal"
		if e.Unit != "" {
			source = "journal/" + e.Unit
		} else if e.Identifier != "" {
			source = "journal/" + e.Identifier
		}
		level := journalLevel(e.Priority)
		if level == "" {
			level = DetectLevel(msg)
		}
		entries = append(entries, proto.LogEntry{TimestampNs: us * 1000, Source: source, Level: level, Line: clip(msg)})
		if len(entries) >= max {
			break
		}
	}
	return entries, next, nil
}

// MESSAGE is a string, or an array of bytes when it isn't valid UTF-8.
func journalMessage(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var b []byte
	var ints []int
	if json.Unmarshal(raw, &ints) == nil {
		for _, i := range ints {
			b = append(b, byte(i))
		}
		return string(b)
	}
	return ""
}
