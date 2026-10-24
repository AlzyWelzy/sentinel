package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
