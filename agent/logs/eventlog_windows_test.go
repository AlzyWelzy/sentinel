package logs

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Writes a real event and reads it back through wevtutil.
func TestReadEventLogWindows(t *testing.T) {
	_, last, err := readEventLog("Application", 0, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	marker := fmt.Sprintf("sentinel test %d", time.Now().UnixNano())
	if out, err := exec.Command("eventcreate", "/T", "WARNING", "/ID", "999", "/L", "APPLICATION", "/SO", "SentinelTest", "/D", marker).CombinedOutput(); err != nil {
		t.Skipf("eventcreate (needs admin): %v %s", err, out)
	}
	var found bool
	for i := 0; i < 10 && !found; i++ {
		time.Sleep(500 * time.Millisecond)
		entries, next, err := readEventLog("Application", last, true, 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.Contains(e.Line, marker) {
				found = true
				if e.Source != "eventlog/Application/SentinelTest" || e.Level != "warning" {
					t.Fatalf("entry %+v", e)
				}
			}
		}
		last = next
	}
	if !found {
		t.Fatal("event not read back")
	}
	// Nothing is shipped twice.
	entries, _, _ := readEventLog("Application", last, true, 100)
	for _, e := range entries {
		if strings.Contains(e.Line, marker) {
			t.Fatal("event read twice")
		}
	}
}
