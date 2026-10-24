package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/example-org/pulsegrid/proto"
)

// spool keeps every collected batch on disk until ingest accepts it, so
// network outages and agent restarts lose nothing. When it's full the oldest
// batches go first: recent data matters more than a gap from long ago.
type spool struct {
	dir string
	max int
}

func newSpool(stateDir string, max int) (*spool, error) {
	dir := filepath.Join(stateDir, "spool")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &spool{dir: dir, max: max}, nil
}

func (s *spool) add(b proto.Batch) error {
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	// Zero-padded timestamps sort lexically in time order.
	name := filepath.Join(s.dir, fmt.Sprintf("%020d.json", b.TimestampMs))
	if err := os.WriteFile(name, data, 0o600); err != nil {
		return err
	}
	return s.trim()
}

func (s *spool) files() ([]string, error) {
	names, err := filepath.Glob(filepath.Join(s.dir, "*.json"))
	sort.Strings(names)
	return names, err
}

func (s *spool) trim() error {
	names, err := s.files()
	if err != nil {
		return err
	}
	for len(names) > s.max {
		os.Remove(names[0])
		names = names[1:]
	}
	return nil
}

// oldest returns up to n batches, oldest first, with the files they came from.
func (s *spool) oldest(n int) ([]proto.Batch, []string, error) {
	names, err := s.files()
	if err != nil {
		return nil, nil, err
	}
	if len(names) > n {
		names = names[:n]
	}
	batches := make([]proto.Batch, 0, len(names))
	used := make([]string, 0, len(names))
	for _, name := range names {
		data, err := os.ReadFile(name)
		var b proto.Batch
		if err != nil || json.Unmarshal(data, &b) != nil {
			os.Remove(name) // unreadable; nothing to retry
			continue
		}
		batches = append(batches, b)
		used = append(used, name)
	}
	return batches, used, nil
}

func (s *spool) remove(names []string) {
	for _, name := range names {
		os.Remove(name)
	}
}
