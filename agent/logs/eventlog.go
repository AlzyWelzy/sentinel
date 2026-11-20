package logs

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/AlzyWelzy/sentinel/proto"
)

// Windows Event Log, read with wevtutil (part of every Windows since Vista):
// eventlog = System, Application. Each channel remembers the last record ID
// shipped; a channel seen for the first time starts at its newest record (no
// backfill).

type winEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		Level       string `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		EventRecordID int64 `xml:"EventRecordID"`
	} `xml:"System"`
	RenderingInfo struct {
		Message string `xml:"Message"`
		Level   string `xml:"Level"`
	} `xml:"RenderingInfo"`
	EventData struct {
		Data []string `xml:"Data"`
	} `xml:"EventData"`
}

var wevtutil = "wevtutil"

// readEventLog returns up to max events of channel after record ID last.
// A channel not known yet only has its newest record ID found.
func readEventLog(channel string, last int64, known bool, max int) ([]proto.LogEntry, int64, error) {
	if _, err := exec.LookPath(wevtutil); err != nil {
		return nil, last, errors.New("wevtutil not found (the event log is Windows only)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var args []string
	if !known {
		args = []string{"qe", channel, "/c:1", "/rd:true", "/f:xml"}
	} else {
		args = []string{"qe", channel, fmt.Sprintf("/q:*[System[EventRecordID>%d]]", last),
			"/c:" + strconv.Itoa(max), "/f:RenderedXml"}
	}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, wevtutil, args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, last, fmt.Errorf("%s: %s", channel, msg)
	}
	events := parseEvents(out)
	if !known {
		var newest int64 // an empty channel starts before its first record
		for _, e := range events {
			newest = max64(newest, e.System.EventRecordID)
		}
		return nil, newest, nil
	}
	var entries []proto.LogEntry
	next := last
	for _, e := range events {
		if e.System.EventRecordID <= last {
			continue
		}
		next = max64(next, e.System.EventRecordID)
		t, err := time.Parse(time.RFC3339Nano, e.System.TimeCreated.SystemTime)
		if err != nil {
			t = time.Now()
		}
		msg := strings.Join(strings.Fields(e.RenderingInfo.Message), " ")
		if msg == "" {
			// No message template installed for the provider: the raw data.
			msg = strings.Join(e.EventData.Data, "; ")
		}
		line := fmt.Sprintf("%s %s: %s", e.System.Provider.Name, e.System.EventID, msg)
		entries = append(entries, proto.LogEntry{
			TimestampNs: t.UnixNano(),
			Source:      "eventlog/" + channel + "/" + e.System.Provider.Name,
			Level:       eventLevel(e.System.Level, line),
			Line:        clip(line),
		})
	}
	return entries, next, nil
}

// parseEvents reads wevtutil's output: <Event> elements one after another,
// with no root element around them.
func parseEvents(b []byte) []winEvent {
	d := xml.NewDecoder(bytes.NewReader(b))
	var out []winEvent
	for {
		tok, err := d.Token()
		if err == io.EOF || (err != nil && tok == nil) {
			return out
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "Event" {
			var e winEvent
			if d.DecodeElement(&e, &se) == nil {
				out = append(out, e)
			}
		}
	}
}

// eventLevel maps Windows levels (1 critical, 2 error, 3 warning, 4 and 0
// information, 5 verbose).
func eventLevel(l, line string) string {
	switch l {
	case "1", "2":
		return "error"
	case "3":
		return "warning"
	case "5":
		return "debug"
	case "4", "0":
		return "info"
	}
	return DetectLevel(line)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
