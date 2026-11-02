package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/example-org/pulsegrid/agent/plugins"
)

// cmdEnableHardware: pulsegrid-agent enable-hardware [--remove]. Run as
// root. Finds smartctl and ipmitool, writes plugins.d/smart.conf and
// ipmi.conf, and lets the agent's user run exactly those commands as root.
func cmdEnableHardware(args []string) error {
	fs := flag.NewFlagSet("enable-hardware", flag.ExitOnError)
	configDir := fs.String("config-dir", defaultConfigDir(), "agent config directory")
	user := fs.String("user", defaultServiceUser(), "the agent's user, for the sudoers rule")
	remove := fs.Bool("remove", false, "stop hardware monitoring and remove the sudo rule")
	fs.Parse(args)
	if runtime.GOOS == "windows" {
		return errors.New("hardware monitoring is for Linux and BSD servers")
	}
	if os.Geteuid() != 0 {
		return errors.New("run as root: sudo pulsegrid-agent enable-hardware")
	}
	dir := filepath.Join(*configDir, "plugins.d")
	if *remove {
		for _, f := range []string{"smart.conf", "ipmi.conf"} {
			os.Remove(filepath.Join(dir, f))
		}
		os.Remove(hardwareSudoers())
		removeHardwareTimer()
		if err := systemdSudoDropIn(actionsUseSudo(*configDir)); err != nil {
			return err
		}
		fmt.Println("Hardware monitoring removed.")
		return nil
	}
	// Without sudo, a root timer runs the commands instead (systemd only).
	_, haveSudo := findTool("sudo")
	if !haveSudo {
		if _, err := os.Stat("/run/systemd/system"); err != nil {
			return errors.New("sudo isn't installed; install it first")
		}
	} else if _, err := os.Stat(filepath.Dir(hardwareSudoers())); err != nil {
		return fmt.Errorf("%s doesn't exist; is sudo installed?", filepath.Dir(hardwareSudoers()))
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	var commands [][]string
	var found []string

	if smartctl, ok := findTool("smartctl"); ok {
		devices, err := scanSmart(smartctl)
		switch {
		case err != nil:
			fmt.Printf("smartctl: %v\n", err)
		case len(devices) == 0:
			fmt.Println("smartctl found no disks with SMART (virtual disks usually have none).")
			os.Remove(filepath.Join(dir, "smart.conf")) // a stale list would fail forever
		default:
			var list []string
			for _, d := range devices {
				commands = append(commands, plugins.SmartArgs(smartctl, d[0], d[1]))
				list = append(list, d[0]+":"+d[1])
			}
			conf := fmt.Sprintf("# Disk health. Written by pulsegrid-agent enable-hardware.\ntype = smart\nsmartctl = %s\ndevices = %s\n", smartctl, strings.Join(list, ","))
			if err := os.WriteFile(filepath.Join(dir, "smart.conf"), []byte(conf), 0o644); err != nil {
				return err
			}
			found = append(found, fmt.Sprintf("SMART on %d disk(s): %s", len(devices), strings.Join(list, ", ")))
		}
	} else {
		fmt.Println("smartctl isn't installed (package smartmontools); skipping disk health.")
	}

	if ipmitool, ok := findTool("ipmitool"); ok && hasBMC() && !ipmiReads(ipmitool) {
		os.Remove(filepath.Join(dir, "ipmi.conf"))
		fmt.Println("The BMC returns no sensor readings; skipping board sensors.")
	} else if ok && hasBMC() {
		commands = append(commands, plugins.IPMIArgs(ipmitool))
		conf := fmt.Sprintf("# Board sensors. Written by pulsegrid-agent enable-hardware.\ntype = ipmi\nipmitool = %s\n", ipmitool)
		if err := os.WriteFile(filepath.Join(dir, "ipmi.conf"), []byte(conf), 0o644); err != nil {
			return err
		}
		found = append(found, "IPMI sensors")
	} else if ok {
		os.Remove(filepath.Join(dir, "ipmi.conf"))
		fmt.Println("ipmitool is installed but there's no BMC (/dev/ipmi0); load the ipmi_devintf module on physical servers.")
	} else {
		fmt.Println("ipmitool isn't installed; skipping board sensors (physical servers only).")
	}

	if len(commands) == 0 {
		return errors.New("nothing to monitor here")
	}
	if !haveSudo {
		if err := installHardwareTimer(*configDir); err != nil {
			return err
		}
		fmt.Printf("Enabled: %s (sudo isn't installed: a root timer collects every 2 minutes).\n", strings.Join(found, "; "))
		return nil
	}
	removeHardwareTimer()
	if err := writeHardwareSudoers(commands, *user); err != nil {
		return err
	}
	if err := systemdSudoDropIn(true); err != nil {
		return err
	}
	fmt.Printf("Enabled: %s.\nThe agent picks it up within a minute; check with: sudo -u %s pulsegrid-agent plugins\n", strings.Join(found, "; "), *user)
	return nil
}

// scanSmart lists disks smartctl can read, as (device, type).
func scanSmart(smartctl string) ([][2]string, error) {
	out, err := exec.Command(smartctl, "--scan-open", "-j").Output()
	if len(out) == 0 && err != nil {
		return nil, err
	}
	var scan struct {
		Devices []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(out, &scan); err != nil {
		return nil, errors.New("unreadable smartctl --scan-open output")
	}
	var devices [][2]string
	for _, d := range scan.Devices {
		// Probe each: only disks that actually answer with SMART data.
		raw, _ := exec.Command(smartctl, plugins.SmartArgs(smartctl, d.Name, d.Type)[1:]...).Output()
		var r struct {
			SmartStatus *struct{} `json:"smart_status"`
		}
		if json.Unmarshal(raw, &r) == nil && r.SmartStatus != nil {
			devices = append(devices, [2]string{d.Name, d.Type})
		}
	}
	return devices, nil
}

func hasBMC() bool {
	for _, p := range []string{"/dev/ipmi0", "/dev/ipmi/0", "/dev/ipmidev/0"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func writeHardwareSudoers(commands [][]string, user string) error {
	var lines []string
	for _, c := range commands {
		lines = append(lines, fmt.Sprintf("%s ALL=(root) NOPASSWD: %s", user, sudoersEscape(strings.Join(c, " "))))
	}
	sort.Strings(lines)
	content := "# Managed by pulsegrid-agent enable-hardware: read-only hardware queries.\n" + strings.Join(lines, "\n") + "\n"
	if _, err := os.Stat(filepath.Dir(hardwareSudoers())); err != nil {
		return fmt.Errorf("%s doesn't exist; is sudo installed?", filepath.Dir(hardwareSudoers()))
	}
	tmp := hardwareSudoers() + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o440); err != nil {
		return err
	}
	if visudo, ok := findTool("visudo"); ok {
		if out, err := exec.Command(visudo, "-cf", tmp).CombinedOutput(); err != nil {
			os.Remove(tmp)
			return fmt.Errorf("sudoers rule rejected by visudo: %s", strings.TrimSpace(string(out)))
		}
	}
	return os.Rename(tmp, hardwareSudoers())
}

func hardwareUsesSudo() bool {
	_, err := os.Stat(hardwareSudoers())
	return err == nil
}

func actionsUseSudo(configDir string) bool {
	m, err := loadActions(configDir)
	if err != nil {
		return false
	}
	for _, args := range m {
		if len(args) > 1 && filepath.Base(args[0]) == "sudo" {
			return true
		}
	}
	return false
}

const (
	hardwareUnit      = "pulsegrid-agent-hardware"
	hardwareUnitDir   = "/etc/systemd/system/"
	hardwareTimerFile = hardwareUnitDir + hardwareUnit + ".timer"
)

// installHardwareTimer runs `hardware-cache` as root every 2 minutes, for
// servers without sudo, and once right away.
func installHardwareTimer(configDir string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if p, err := filepath.EvalSymlinks(self); err == nil {
		self = p
	}
	service := fmt.Sprintf("[Unit]\nDescription=Pulsegrid agent: read disk and board sensors as root\n\n"+
		"[Service]\nType=oneshot\nExecStart=%s hardware-cache --config-dir %s\nNice=10\nIOSchedulingClass=idle\n", self, configDir)
	timer := "[Unit]\nDescription=Pulsegrid agent: hardware readings every 2 minutes\n\n" +
		"[Timer]\nOnBootSec=1min\nOnUnitActiveSec=2min\nAccuracySec=15s\n\n[Install]\nWantedBy=timers.target\n"
	if err := os.WriteFile(hardwareUnitDir+hardwareUnit+".service", []byte(service), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(hardwareTimerFile, []byte(timer), 0o644); err != nil {
		return err
	}
	systemctl, ok := findTool("systemctl")
	if !ok {
		return errors.New("systemctl not found")
	}
	exec.Command(systemctl, "daemon-reload").Run()
	if out, err := exec.Command(systemctl, "enable", "--now", hardwareUnit+".timer").CombinedOutput(); err != nil {
		return fmt.Errorf("enabling %s.timer: %s", hardwareUnit, strings.TrimSpace(string(out)))
	}
	// First readings now rather than in a minute.
	return cmdHardwareCache([]string{"--config-dir", configDir})
}

func removeHardwareTimer() {
	if _, err := os.Stat(hardwareTimerFile); err != nil {
		return
	}
	if systemctl, ok := findTool("systemctl"); ok {
		exec.Command(systemctl, "disable", "--now", hardwareUnit+".timer").Run()
	}
	os.Remove(hardwareTimerFile)
	os.Remove(hardwareUnitDir + hardwareUnit + ".service")
	if systemctl, ok := findTool("systemctl"); ok {
		exec.Command(systemctl, "daemon-reload").Run()
	}
	os.RemoveAll(plugins.HardwareCacheDir)
}

// cmdHardwareCache: pulsegrid-agent hardware-cache. As root, runs exactly the
// commands the SMART/IPMI plugin files ask for and caches their output for
// the agent, which can't run them itself without sudo.
func cmdHardwareCache(args []string) error {
	fs := flag.NewFlagSet("hardware-cache", flag.ExitOnError)
	configDir := fs.String("config-dir", defaultConfigDir(), "agent config directory")
	fs.Parse(args)
	if os.Geteuid() != 0 {
		return errors.New("run as root")
	}
	if err := os.MkdirAll(plugins.HardwareCacheDir, 0o755); err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, c := range hardwareCommands(filepath.Join(*configDir, "plugins.d")) {
		path := plugins.HardwareCacheFile(c)
		keep[filepath.Base(path)] = true
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		// smartctl's exit status is a bitmask that's non-zero for failing
		// disks too; the output says what happened.
		out, _ := exec.CommandContext(ctx, c[0], c[1:]...).Output()
		cancel()
		tmp := path + ".tmp"
		if os.WriteFile(tmp, out, 0o644) == nil {
			os.Rename(tmp, path)
		}
	}
	entries, _ := os.ReadDir(plugins.HardwareCacheDir)
	for _, e := range entries {
		if !keep[e.Name()] {
			os.Remove(filepath.Join(plugins.HardwareCacheDir, e.Name()))
		}
	}
	return nil
}

// hardwareCommands lists the privileged commands that enable-hardware's
// plugin files will run; nil when there are none.
func hardwareCommands(pdir string) [][]string {
	var out [][]string
	for _, name := range []string{"smart.conf", "ipmi.conf"} {
		f, err := os.Open(filepath.Join(pdir, name))
		if err != nil {
			continue
		}
		kv, err := plugins.ParseKV(f)
		f.Close()
		if err != nil {
			continue
		}
		switch kv["type"] {
		case "smart":
			tool := kv["smartctl"]
			if tool == "" {
				tool = "/usr/sbin/smartctl"
			}
			for _, d := range plugins.SmartDevices(kv["devices"]) {
				out = append(out, plugins.SmartArgs(tool, d[0], d[1]))
			}
		case "ipmi":
			tool := kv["ipmitool"]
			if tool == "" {
				tool = "/usr/bin/ipmitool"
			}
			out = append(out, plugins.IPMIArgs(tool))
		}
	}
	return out
}

// ipmiReads reports whether the BMC returns any sensor readings (as root).
func ipmiReads(ipmitool string) bool {
	r := plugins.Collect(context.Background(), []plugins.Config{{Name: "probe", Type: "ipmi", Settings: map[string]string{"ipmitool": ipmitool}}})
	return r[0].Status.OK
}
