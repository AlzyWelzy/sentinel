//go:build !windows

package main

import "testing"

// Cron gives a minimal PATH; the restart tools must still be found.
func TestFindToolWithoutSbinInPath(t *testing.T) {
	t.Setenv("PATH", "/nonexistent")
	if _, ok := findTool("sh"); !ok {
		t.Fatal("expected to find sh in the standard directories")
	}
	if _, ok := findTool("definitely-not-a-real-tool"); ok {
		t.Fatal("found a tool that doesn't exist")
	}
}
