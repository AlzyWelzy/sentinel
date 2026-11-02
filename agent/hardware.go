package main

import (
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

	"github.com/example-org/pulsegrid/agent/plugins"
)

const hardwareSudoers = "/etc/sudoers.d/pulsegrid-hardware"

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
		os.Remove(hardwareSudoers)
		if err := systemdSudoDropIn(actionsUseSudo(*configDir)); err != nil {
			return err
		}
		fmt.Println("Hardware monitoring removed.")
		return nil
	}
	// Without sudo the plugins could never run; don't leave them failing.
	if _, ok := findTool("sudo"); !ok {
		return errors.New("sudo isn't installed; install it first")
	}
	if _, err := os.Stat(filepath.Dir(hardwareSudoers)); err != nil {
		return fmt.Errorf("%s doesn't exist; install sudo first", filepath.Dir(hardwareSudoers))
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

	if ipmitool, ok := findTool("ipmitool"); ok && hasBMC() {
		commands = append(commands, plugins.IPMIArgs(ipmitool))
		conf := fmt.Sprintf("# Board sensors. Written by pulsegrid-agent enable-hardware.\ntype = ipmi\nipmitool = %s\n", ipmitool)
		if err := os.WriteFile(filepath.Join(dir, "ipmi.conf"), []byte(conf), 0o644); err != nil {
			return err
		}
		found = append(found, "IPMI sensors")
	} else if ok {
		fmt.Println("ipmitool is installed but there's no BMC (/dev/ipmi0); load the ipmi_devintf module on physical servers.")
	} else {
		fmt.Println("ipmitool isn't installed; skipping board sensors (physical servers only).")
	}

	if len(commands) == 0 {
		return errors.New("nothing to monitor here")
	}
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
	if _, err := os.Stat(filepath.Dir(hardwareSudoers)); err != nil {
		return fmt.Errorf("%s doesn't exist; is sudo installed?", filepath.Dir(hardwareSudoers))
	}
	tmp := hardwareSudoers + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o440); err != nil {
		return err
	}
	if visudo, ok := findTool("visudo"); ok {
		if out, err := exec.Command(visudo, "-cf", tmp).CombinedOutput(); err != nil {
			os.Remove(tmp)
			return fmt.Errorf("sudoers rule rejected by visudo: %s", strings.TrimSpace(string(out)))
		}
	}
	return os.Rename(tmp, hardwareSudoers)
}

func hardwareUsesSudo() bool {
	_, err := os.Stat(hardwareSudoers)
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
