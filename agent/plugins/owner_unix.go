//go:build !windows

package plugins

import (
	"fmt"
	"os"
	"syscall"
)

// checkOwnership refuses files the agent itself could have written: they
// must be owned by root and not writable by group or others.
func CheckOwnership(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or others; run chmod go-w on it", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if ok && st.Uid != 0 && !allowUserOwned {
		return fmt.Errorf("%s must be owned by root", path)
	}
	return nil
}

// allowUserOwned lets tests use files in a temp dir, which belong to the tester.
var allowUserOwned = false
