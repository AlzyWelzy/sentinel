//go:build linux || darwin

package plugins

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A refused sudo call isn't repeated within the backoff, so sudo doesn't
// log (and mail root) on every collection.
func TestRunPrivilegedBacksOffAfterRefusal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs directly as root")
	}
	dir := t.TempDir()
	count := filepath.Join(dir, "count")
	sudo := "#!/bin/sh\necho x >> " + count + "\necho 'sudo: a password is required' >&2\nexit 1\n"
	os.WriteFile(filepath.Join(dir, "sudo"), []byte(sudo), 0o755)
	t.Setenv("PATH", dir)
	for i := 0; i < 3; i++ {
		if _, err := runPrivileged(context.Background(), []string{"/usr/sbin/smartctl", "-j", "/dev/test"}); err == nil || !strings.Contains(err.Error(), "not allowed") {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	b, _ := os.ReadFile(count)
	if n := strings.Count(string(b), "x"); n != 1 {
		t.Fatalf("sudo ran %d times, want 1", n)
	}
}
