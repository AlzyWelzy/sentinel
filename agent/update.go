package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// cmdUpdate replaces the installed binary with the version ingest advertises.
// It runs privileged on a schedule (systemd timer, cron, or a Windows
// scheduled task; see the installers), separately from the agent itself,
// which runs unprivileged and can't write to its own binary.
func cmdUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "where the agent keeps its state")
	restart := fs.String("restart", "", "service to restart after updating (e.g. sentinel-agent)")
	fs.Parse(args)

	st, err := loadState(*stateDir)
	if err != nil {
		return fmt.Errorf("not registered: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	c := newClient()
	cfg, err := c.config(ctx, st.IngestURL, st.HostToken)
	if err != nil && st.BootstrapURL != st.IngestURL {
		cfg, err = c.config(ctx, st.BootstrapURL, st.HostToken)
	}
	if err != nil {
		return fmt.Errorf("fetching config: %w", err)
	}
	if cfg.LatestVersion == "" || cfg.DownloadURL == "" {
		fmt.Println("no version advertised; nothing to do")
		return nil
	}
	if cfg.LatestVersion == version {
		fmt.Printf("already on %s\n", version)
		// Servers installed before autoconfig get it here, as root, once.
		if maybeAutoconfigure() && *restart != "" {
			return restartService(*restart)
		}
		return nil
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return err
	}
	asset := fmt.Sprintf("sentinel-agent-%s-%s%s", runtime.GOOS, runtime.GOARCH, exeSuffix)
	base := strings.TrimRight(cfg.DownloadURL, "/") + "/agent/" + cfg.LatestVersion + "/" + asset

	sum, err := fetchChecksum(ctx, c.http, base+".sha256")
	if err != nil {
		return err
	}
	// Download next to the binary so the final rename stays on one filesystem
	// and is atomic: the agent is never left with a half-written executable.
	tmp, err := os.CreateTemp(filepath.Dir(self), ".sentinel-agent-update-*"+exeSuffix)
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := download(ctx, c.http, base, tmp, sum); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return err
	}
	// Refuse a binary that can't even start on this machine.
	out, err := exec.CommandContext(ctx, tmp.Name(), "version").Output()
	if err != nil || strings.TrimSpace(string(out)) != cfg.LatestVersion {
		return fmt.Errorf("downloaded binary failed its self-check (%q, %v)", strings.TrimSpace(string(out)), err)
	}
	if err := replaceExecutable(tmp.Name(), self); err != nil {
		return err
	}
	fmt.Printf("updated %s -> %s\n", version, cfg.LatestVersion)
	// Let the new binary set up whatever it knows about now, rather than an
	// hour from now: as root, and only once per autoconfig revision.
	if privileged() {
		cmd := exec.CommandContext(ctx, self, "autoconfig", "--if-due")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		cmd.Run()
	}

	if *restart != "" {
		return restartService(*restart)
	}
	return nil
}

func fetchChecksum(ctx context.Context, hc *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checksum download: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 || len(fields[0]) != 64 {
		return "", errors.New("malformed checksum file")
	}
	return fields[0], nil
}

func download(ctx context.Context, hc *http.Client, url string, dst io.Writer, wantSHA256 string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	// Binaries are larger than the API client's timeout budget assumes.
	resp, err := (&http.Client{Timeout: 5 * time.Minute, Transport: hc.Transport}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("binary download: %s", resp.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(dst, h), io.LimitReader(resp.Body, 200<<20)); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantSHA256 {
		return fmt.Errorf("checksum mismatch: got %s, want %s", got, wantSHA256)
	}
	return nil
}
