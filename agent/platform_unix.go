//go:build !windows

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

const exeSuffix = ""

func defaultStateDir() string { return "/var/lib/pulsegrid" }

// runAsService reports false: on Unix the init system (systemd, OpenRC,
// rc.d) runs `pulsegrid-agent run` as a normal foreground process.
func runAsService(func(context.Context)) (bool, error) { return false, nil }

// replaceExecutable swaps in the new binary. rename(2) is atomic and works on
// a running executable: the old inode stays alive until the process exits.
func replaceExecutable(newPath, target string) error { return os.Rename(newPath, target) }

// restartService restarts the agent with whichever init system is present.
// FreeBSD, NetBSD and OpenBSD name the service with an underscore because
// rc.subr variables can't contain dashes.
func restartService(name string) error {
	try := [][]string{
		{"systemctl", "restart", name},
		{"rc-service", name, "restart"},          // OpenRC (Alpine)
		{"rcctl", "restart", underscore(name)},   // OpenBSD
		{"service", underscore(name), "restart"}, // FreeBSD, NetBSD
	}
	for _, cmd := range try {
		if path, ok := findTool(cmd[0]); ok {
			return exec.Command(path, cmd[1:]...).Run()
		}
	}
	return errors.New("no supported init system found to restart " + name)
}

// findTool looks in PATH and then the usual sbin directories: cron and
// non-interactive root shells (NetBSD in particular) often leave those out.
func findTool(name string) (string, bool) {
	if path, err := exec.LookPath(name); err == nil {
		return path, true
	}
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin", "/bin"} {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return path, true
		}
	}
	return "", false
}

func underscore(name string) string {
	b := []byte(name)
	for i, c := range b {
		if c == '-' {
			b[i] = '_'
		}
	}
	return string(b)
}

func defaultConfigDir() string { return "/etc/pulsegrid" }

func defaultServiceUser() string {
	if runtime.GOOS == "openbsd" {
		return "_pulsegrid"
	}
	return "pulsegrid"
}
