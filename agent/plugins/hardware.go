package plugins

// Hardware: disk health (smartctl) and board sensors (ipmitool). Both need
// root. `sentinel-agent enable-hardware` writes these plugin files and a
// sudoers rule for exactly the command lines below, so the agent can run
// them through `sudo -n` and nothing else.
//
//	type = smart
//	smartctl = /usr/sbin/smartctl
//	devices = /dev/sda:sat,/dev/nvme0:nvme
//
//	type = ipmi
//	ipmitool = /usr/bin/ipmitool

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

// SmartArgs is the exact smartctl command for one device; the sudoers rule
// written by enable-hardware must match it word for word.
func SmartArgs(smartctl, device, devType string) []string {
	args := []string{smartctl, "-j", "-H", "-A", "-i"}
	if devType != "" {
		args = append(args, "-d", devType)
	}
	return append(args, device)
}

// IPMIArgs is the exact ipmitool command.
func IPMIArgs(ipmitool string) []string {
	return []string{ipmitool, "-c", "sdr", "elist", "full"}
}

// runPrivileged runs a command as root: directly when the agent is root
// (containers), otherwise through sudo -n, which fails at once without a rule.
func runPrivileged(ctx context.Context, args []string) ([]byte, error) {
	if !filepath.IsAbs(args[0]) {
		return nil, fmt.Errorf("%s must be an absolute path", args[0])
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	if os.Geteuid() != 0 {
		sudo, err := exec.LookPath("sudo")
		if err != nil {
			sudo, err = "/usr/bin/sudo", nil
			if _, serr := os.Stat(sudo); serr != nil {
				err = serr
			}
		}
		if err != nil {
			// No sudo: a root timer runs these commands and caches the output.
			return readHardwareCache(args)
		}
		cmd = exec.CommandContext(ctx, sudo, append([]string{"-n"}, args...)...)
	}
	key := strings.Join(args, " ")
	refusedMu.Lock()
	until := refused[key]
	refusedMu.Unlock()
	if time.Now().Before(until) {
		return nil, errors.New("not allowed to run it; run: sudo sentinel-agent enable-hardware")
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if strings.Contains(stderr.String(), "a password is required") || strings.Contains(stderr.String(), "not allowed") {
		// sudo logs (and may mail root about) every refusal; ask again in an
		// hour, by when the update job has usually repaired the rule.
		refusedMu.Lock()
		refused[key] = time.Now().Add(refuseBackoff)
		refusedMu.Unlock()
		return nil, errors.New("not allowed to run it; run: sudo sentinel-agent enable-hardware")
	}
	return stdout.Bytes(), err
}

// HardwareCacheDir is where `sentinel-agent hardware-cache`, run as root by
// a timer on servers without sudo, leaves each command's output.
var HardwareCacheDir = "/var/lib/sentinel/hardware"

// HardwareCacheFile names the cached output of one command line.
func HardwareCacheFile(args []string) string {
	sum := sha256.Sum256([]byte(strings.Join(args, "\x00")))
	return filepath.Join(HardwareCacheDir, hex.EncodeToString(sum[:12])+".out")
}

// hardwareCacheMaxAge: older output means the timer stopped.
const hardwareCacheMaxAge = 10 * time.Minute

func readHardwareCache(args []string) ([]byte, error) {
	path := HardwareCacheFile(args)
	if msg, err := os.ReadFile(path + ".err"); err == nil {
		return nil, fmt.Errorf("%s (as root, by the hardware timer)", strings.TrimSpace(string(msg)))
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, errors.New("sudo isn't installed and the hardware timer hasn't run yet; run sentinel-agent enable-hardware as root")
	}
	if age := time.Since(fi.ModTime()); age > hardwareCacheMaxAge {
		return nil, fmt.Errorf("the hardware timer last ran %s ago; check: systemctl status sentinel-agent-hardware.timer", age.Round(time.Minute))
	}
	return os.ReadFile(path)
}

// refused holds, per command line, when sudo may be asked again after
// refusing it.
var (
	refusedMu     sync.Mutex
	refused       = map[string]time.Time{}
	refuseBackoff = time.Hour
)

type smartReport struct {
	ModelName   string `json:"model_name"`
	SmartStatus *struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature *struct {
		Current float64 `json:"current"`
	} `json:"temperature"`
	PowerOnTime *struct {
		Hours float64 `json:"hours"`
	} `json:"power_on_time"`
	ATA *struct {
		Table []struct {
			ID  int `json:"id"`
			Raw struct {
				Value float64 `json:"value"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	NVMe *struct {
		CriticalWarning float64 `json:"critical_warning"`
		AvailableSpare  float64 `json:"available_spare"`
		PercentageUsed  float64 `json:"percentage_used"`
		MediaErrors     float64 `json:"media_errors"`
	} `json:"nvme_smart_health_information_log"`
	Smartctl struct {
		Messages []struct {
			String string `json:"string"`
		} `json:"messages"`
	} `json:"smartctl"`
}

// ATA attributes worth alerting on, by id.
var ataAttrs = map[int]string{
	5:   "reallocated_sectors",
	187: "uncorrectable_errors",
	197: "pending_sectors",
	198: "offline_uncorrectable",
	199: "crc_errors",
}

// parseSmart turns smartctl -j output into samples for one device.
func parseSmart(out []byte, device string) ([]proto.Sample, error) {
	var r smartReport
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, fmt.Errorf("%s: unreadable smartctl output", device)
	}
	if r.SmartStatus == nil {
		msg := "no SMART data"
		if len(r.Smartctl.Messages) > 0 {
			msg = r.Smartctl.Messages[0].String
		}
		return nil, fmt.Errorf("%s: %s", device, msg)
	}
	dev := filepath.Base(device)
	l := []string{"device", dev}
	s := []proto.Sample{sample("sentinel_custom_smart_healthy", boolValue(r.SmartStatus.Passed), "device", dev, "model", r.ModelName)}
	if r.Temperature != nil && r.Temperature.Current > 0 {
		s = append(s, sample("sentinel_custom_smart_temperature_celsius", r.Temperature.Current, l...))
	}
	if r.PowerOnTime != nil {
		s = append(s, sample("sentinel_custom_smart_power_on_hours", r.PowerOnTime.Hours, l...))
	}
	if r.ATA != nil {
		for _, a := range r.ATA.Table {
			if name, ok := ataAttrs[a.ID]; ok {
				s = append(s, sample("sentinel_custom_smart_"+name, a.Raw.Value, l...))
			}
		}
	}
	if r.NVMe != nil {
		s = append(s,
			sample("sentinel_custom_smart_nvme_percentage_used", r.NVMe.PercentageUsed, l...),
			sample("sentinel_custom_smart_nvme_available_spare", r.NVMe.AvailableSpare, l...),
			sample("sentinel_custom_smart_nvme_media_errors", r.NVMe.MediaErrors, l...),
			sample("sentinel_custom_smart_nvme_critical_warning", r.NVMe.CriticalWarning, l...),
		)
	}
	return s, nil
}

// SmartDevices parses "devices = /dev/sda:sat,/dev/bus/0:megaraid,1". A
// type can itself hold a comma (megaraid,N), so a piece that isn't a path
// belongs to the type before it.
func SmartDevices(v string) [][2]string {
	var out [][2]string
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if !strings.HasPrefix(item, "/") && len(out) > 0 {
			out[len(out)-1][1] += "," + item
			continue
		}
		dev, typ, _ := strings.Cut(item, ":")
		out = append(out, [2]string{dev, typ})
	}
	return out
}

var devicePath = regexp.MustCompile(`^/dev/[A-Za-z0-9_/.-]+$`)
var devType = regexp.MustCompile(`^[a-z0-9,_+-]*$`)

func collectSmart(ctx context.Context, c Config) ([]proto.Sample, error) {
	smartctl := orDefault(c.Settings["smartctl"], "/usr/sbin/smartctl")
	devices := SmartDevices(c.Settings["devices"])
	if len(devices) == 0 {
		return nil, errors.New("no devices; run: sudo sentinel-agent enable-hardware")
	}
	var out []proto.Sample
	var problems []string
	for _, d := range devices {
		if !devicePath.MatchString(d[0]) || !devType.MatchString(d[1]) {
			problems = append(problems, d[0]+": not a device path")
			continue
		}
		raw, err := runPrivileged(ctx, SmartArgs(smartctl, d[0], d[1]))
		// smartctl's exit status is a bitmask that's non-zero for failing
		// disks too; the JSON says what happened.
		if len(raw) == 0 && err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", d[0], err))
			continue
		}
		s, perr := parseSmart(raw, d[0])
		if perr != nil {
			problems = append(problems, perr.Error())
			continue
		}
		out = append(out, s...)
	}
	if len(problems) > 0 && len(out) == 0 {
		return nil, errors.New(strings.Join(problems, "; "))
	}
	return out, nil
}

var sensorName = regexp.MustCompile(`[^A-Za-z0-9 _./+-]`)

// parseIPMI reads `ipmitool -c sdr elist full`:
// name,id,status,entity,reading — e.g. "CPU1 Temp,01h,ok,3.1,45 degrees C".
func parseIPMI(out []byte) ([]proto.Sample, error) {
	r := csv.NewReader(bytes.NewReader(out))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("unreadable ipmitool output: %w", err)
	}
	var s []proto.Sample
	for _, row := range rows {
		if len(row) < 5 {
			continue
		}
		name := strings.TrimSpace(sensorName.ReplaceAllString(row[0], ""))
		status := strings.ToLower(strings.TrimSpace(row[2]))
		if name == "" || status == "ns" {
			continue // no reading (absent sensor)
		}
		reading := strings.Fields(row[4])
		if len(reading) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(reading[0], 64)
		if err != nil {
			// Discrete sensors ("0x01"): report only whether they're ok.
			s = append(s, sample("sentinel_custom_ipmi_sensor_ok", boolValue(status == "ok"), "sensor", name))
			continue
		}
		unit := strings.ToLower(strings.Join(reading[1:], " "))
		switch unit {
		case "degrees c":
			unit = "celsius"
		case "volts":
			unit = "volts"
		case "watts":
			unit = "watts"
		case "amps":
			unit = "amps"
		case "rpm":
			unit = "rpm"
		case "percent":
			unit = "percent"
		}
		s = append(s,
			sample("sentinel_custom_ipmi_sensor", v, "sensor", name, "unit", unit),
			sample("sentinel_custom_ipmi_sensor_ok", boolValue(status == "ok"), "sensor", name),
		)
	}
	if len(s) == 0 {
		return nil, errors.New("no sensor readings (is this a physical server with a BMC?)")
	}
	return s, nil
}

func collectIPMI(ctx context.Context, c Config) ([]proto.Sample, error) {
	raw, err := runPrivileged(ctx, IPMIArgs(orDefault(c.Settings["ipmitool"], "/usr/bin/ipmitool")))
	if err != nil && len(raw) == 0 {
		return nil, fmt.Errorf("ipmitool: %w", err)
	}
	return parseIPMI(raw)
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
