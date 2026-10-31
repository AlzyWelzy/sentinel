//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteNewKeepsExisting(t *testing.T) {
	p := filepath.Join(t.TempDir(), "logs.conf")
	if !writeNew(p, "a\n", 0o644, "") {
		t.Fatal("first write refused")
	}
	if writeNew(p, "b\n", 0o644, "") {
		t.Fatal("overwrote an existing file")
	}
	if b, _ := os.ReadFile(p); string(b) != "a\n" {
		t.Fatalf("content = %q", b)
	}
}

func TestPluginTypesSeesAnyFileName(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main-db.conf"), []byte("type = MySQL\ndsn = x\n"), 0o644)
	if have := pluginTypes(dir); !have["mysql"] || have["redis"] {
		t.Fatalf("types = %v", have)
	}
}
