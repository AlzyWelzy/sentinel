package main

import "testing"

func TestStoredMachineIDIsStable(t *testing.T) {
	dir := t.TempDir()
	first, err := storedMachineID(dir)
	if err != nil || len(first) != 32 {
		t.Fatalf("first id %q, %v", first, err)
	}
	second, err := storedMachineID(dir)
	if err != nil || second != first {
		t.Fatalf("id changed between calls: %q then %q (%v)", first, second, err)
	}
}
