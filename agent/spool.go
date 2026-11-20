package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"

	"github.com/AlzyWelzy/sentinel/proto"
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
	// Leftovers of writes interrupted by a crash.
	if tmps, err := filepath.Glob(filepath.Join(dir, "*.tmp")); err == nil {
		for _, t := range tmps {
			os.Remove(t)
		}
	}
	return &spool{dir: dir, max: max}, nil
}

func (s *spool) add(b proto.Batch) error {
	b.Samples = finiteSamples(b.Samples)
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	// Zero-padded timestamps sort lexically in time order; the random
	// suffix keeps two batches in one millisecond apart.
	var suffix [4]byte
	rand.Read(suffix[:])
	name := filepath.Join(s.dir, fmt.Sprintf("%020d-%x.json", b.TimestampMs, suffix))
	if err := writeAtomic(name, data); err != nil {
		return err
	}
	return s.trim()
}

// writeAtomic writes to a temporary file, syncs it and renames it into
// place, so a crash or power loss leaves the whole batch or nothing (a
// half-written file would be read back as corrupt and discarded).
func writeAtomic(name string, data []byte) error {
	tmp := name + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, name)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
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

// finiteSamples drops NaN and ±Inf values, which JSON can't carry: one would
// fail the whole batch, and every batch after it while the source keeps
// reporting one. Prometheus summaries export NaN for quantiles with no
// observations, and custom scripts can divide by zero.
func finiteSamples(in []proto.Sample) []proto.Sample {
	out := in[:0]
	for _, s := range in {
		if !math.IsNaN(s.Value) && !math.IsInf(s.Value, 0) {
			out = append(out, s)
		}
	}
	return out
}
