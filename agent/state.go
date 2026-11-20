package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/AlzyWelzy/sentinel/proto"
	"os"
	"path/filepath"
	"strings"
)

// state is everything the agent needs to keep across restarts. It holds the
// host token, so it's written 0600 inside a 0700 directory.
type state struct {
	// BootstrapURL is where the agent registered. Kept as a fallback if the
	// ingest URL handed out later stops working.
	BootstrapURL    string `json:"bootstrap_url"`
	IngestURL       string `json:"ingest_url"`
	IntervalSeconds int    `json:"interval_seconds"`
	HostID          string `json:"host_id"`
	HostToken       string `json:"host_token"`
	// From the last config fetch, so watches apply even if ingest is
	// unreachable when the agent starts.
	WatchProcesses []string      `json:"watch_processes,omitempty"`
	WatchServices  []string      `json:"watch_services,omitempty"`
	Checks         []proto.Check `json:"checks,omitempty"`
	ConfigVersion  string        `json:"config_version,omitempty"`
	// Recently run action ids, so a restart doesn't run one twice.
	DoneActions              []string `json:"done_actions,omitempty"`
	InventoryIntervalSeconds int      `json:"inventory_interval_seconds,omitempty"`
}

func statePath(dir string) string { return filepath.Join(dir, "state.json") }

func loadState(dir string) (state, error) {
	var s state
	b, err := os.ReadFile(statePath(dir))
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}

// save writes atomically, so a crash mid-write can't leave a corrupt token file.
func (s state) save(dir string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := statePath(dir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, statePath(dir))
}

// storedMachineID returns the id kept in <dir>/machine-id, creating it on
// first use. It's only used where the OS offers no stable machine id.
func storedMachineID(dir string) (string, error) {
	path := filepath.Join(dir, "machine-id")
	if b, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return id, nil
		}
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)
	return id, os.WriteFile(path, []byte(id+"\n"), 0o600)
}
