package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// On Windows, autoconfig turns on Event Log shipping (System and
// Application) and lets the agent's account read those logs. It runs from
// the update task, as SYSTEM, once per revision, like on Linux.
const (
	autoconfigRev    = "1"
	autoconfigMarker = ".autoconfig" // in the config dir: the revision, or "off"
	autoconfigNote   = "# Written by pulsegrid-agent autoconfig. Delete this line before editing, or updates may refresh the file."
)

func cmdAutoconfig(args []string) error {
	fs := flag.NewFlagSet("autoconfig", flag.ExitOnError)
	configDir := fs.String("config-dir", defaultConfigDir(), "agent config directory")
	off := fs.Bool("off", false, "never autoconfigure this server (updates included)")
	ifDue := fs.Bool("if-due", false, "only if this revision hasn't run and the server isn't opted out (used by update)")
	fs.Parse(args)
	if *ifDue {
		maybeAutoconfigure()
		return nil
	}
	if !privileged() {
		return errors.New("run as Administrator")
	}
	marker := filepath.Join(*configDir, autoconfigMarker)
	if *off {
		return os.WriteFile(marker, []byte("off\n"), 0o644)
	}
	if !autoconfigure(*configDir) {
		fmt.Println("Nothing new to set up.")
	}
	return os.WriteFile(marker, []byte(autoconfigRev+"\n"), 0o644)
}

func maybeAutoconfigure() bool {
	if !privileged() {
		return false
	}
	dir := defaultConfigDir()
	marker := filepath.Join(dir, autoconfigMarker)
	b, _ := os.ReadFile(marker)
	if m := strings.TrimSpace(string(b)); m == "off" || m == autoconfigRev {
		return false
	}
	changed := autoconfigure(dir)
	os.WriteFile(marker, []byte(autoconfigRev+"\n"), 0o644)
	return changed
}

func autoconfigure(dir string) bool {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Println("autoconfig:", err)
		return false
	}
	changed := false
	lc := filepath.Join(dir, "logs.conf")
	if f, err := os.OpenFile(lc, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644); err == nil {
		_, werr := f.WriteString(autoconfigNote + "\r\neventlog = System, Application\r\n")
		f.Close()
		if werr != nil {
			os.Remove(lc)
		} else {
			changed = true
			fmt.Println("autoconfig: log shipping on: System and Application event logs")
		}
	}
	// Event Log Readers (S-1-5-32-573) may read every channel; LOCAL SERVICE
	// (S-1-5-19) is the agent's account. Group names are localized, SIDs aren't.
	ps := `$m = Get-LocalGroupMember -SID S-1-5-32-573 -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -eq 'S-1-5-19' }; ` +
		`if (-not $m) { Add-LocalGroupMember -SID S-1-5-32-573 -Member S-1-5-19; 'added' }`
	if out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).CombinedOutput(); err != nil {
		fmt.Printf("autoconfig: couldn't add the agent to Event Log Readers: %s\n", strings.TrimSpace(string(out)))
	} else if strings.Contains(string(out), "added") {
		changed = true
		fmt.Println("autoconfig: the agent's account may read the event logs")
	}
	return changed
}
