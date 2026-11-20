package plugins

// LVM: volume groups and thin pools, which carry no filesystem of their own
// (Proxmox shared SAN storage, local-lvm), so the disk collector, which
// reads mounted filesystems, never sees them. vgs and lvs need root, so they
// run like the hardware commands: sudo, or the root timer's cache.
//
//	type = lvm
//	vgs = /usr/sbin/vgs
//	lvs = /usr/sbin/lvs
//
// Each storage is reported with the disk metrics under mountpoint
// "lvm:<vg>" or "lvm:<vg>/<pool>", so disk lists and disk alerts cover it.
// A volume group holding a thin pool is reported through its pools only:
// the pool allocates nearly all of it, so the group always looks full. A
// group with a mounted or swap volume (a standard LVM install: root, home)
// isn't reported either: its filesystems already are, and handing all of
// its space to them is normal, not full.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/AlzyWelzy/sentinel/proto"
)

// VGSArgs and LVSArgs are the exact commands; the sudoers rule must match.
// Only fields every lvm2 since 2.02 knows (lv_dm_path isn't one).
func VGSArgs(vgs string) []string {
	return []string{vgs, "--reportformat", "json", "--units", "b", "--nosuffix", "-o", "vg_name,vg_size,vg_free"}
}

func LVSArgs(lvs string) []string {
	return []string{lvs, "--reportformat", "json", "--units", "b", "--nosuffix", "-o", "vg_name,lv_name,lv_size,lv_attr,data_percent,metadata_percent"}
}

func collectLVM(ctx context.Context, c Config) ([]proto.Sample, error) {
	vgOut, err := runPrivileged(ctx, VGSArgs(orDefault(c.Settings["vgs"], "/usr/sbin/vgs")))
	if len(vgOut) == 0 && err != nil {
		return nil, fmt.Errorf("vgs: %w", err)
	}
	lvOut, err := runPrivileged(ctx, LVSArgs(orDefault(c.Settings["lvs"], "/usr/sbin/lvs")))
	if len(lvOut) == 0 && err != nil {
		return nil, fmt.Errorf("lvs: %w", err)
	}
	return parseLVM(vgOut, lvOut, inUseDevices())
}

// inUseDevices are the block devices mounted or used as swap, resolved to
// their real paths (/dev/mapper/vg-root -> /dev/dm-0).
func inUseDevices() map[string]bool {
	out := map[string]bool{}
	for _, f := range []string{"/proc/mounts", "/proc/swaps"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if fields := strings.Fields(line); len(fields) > 0 && strings.HasPrefix(fields[0], "/dev/") {
				out[fields[0]] = true
				out[realPath(fields[0])] = true
			}
		}
	}
	return out
}

func realPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

// mapperPath is the device-mapper name of a logical volume: dashes inside
// the group and volume names are doubled (vg "san-1", lv "vm-1" ->
// /dev/mapper/san--1-vm--1).
func mapperPath(vg, lv string) string {
	return "/dev/mapper/" + strings.ReplaceAll(vg, "-", "--") + "-" + strings.ReplaceAll(lv, "-", "--")
}

type lvmReport struct {
	Report []struct {
		VG []map[string]string `json:"vg"`
		LV []map[string]string `json:"lv"`
	} `json:"report"`
}

func parseLVM(vgOut, lvOut []byte, inUse map[string]bool) ([]proto.Sample, error) {
	var vgs, lvs lvmReport
	if json.Unmarshal(vgOut, &vgs) != nil || json.Unmarshal(lvOut, &lvs) != nil {
		return nil, errors.New("unreadable vgs/lvs output")
	}
	num := func(s string) (float64, bool) {
		v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		return v, err == nil && !math.IsNaN(v) && !math.IsInf(v, 0)
	}
	var out []proto.Sample
	emit := func(mount, device string, total, usedPct float64) {
		usedPct = math.Min(100, math.Max(0, usedPct))
		used := total * usedPct / 100
		out = append(out,
			sample("sentinel_disk_used_percent", usedPct, "mountpoint", mount, "device", device),
			sample("sentinel_disk_free_bytes", total-used, "mountpoint", mount, "device", device),
			sample("sentinel_disk_total_bytes", total, "mountpoint", mount, "device", device, "fstype", "lvm"),
			sample("sentinel_disk_used_bytes", used, "mountpoint", mount, "device", device))
	}
	covered := map[string]bool{} // groups reported through pools or filesystems
	for _, r := range lvs.Report {
		for _, lv := range r.LV {
			vg, name := lv["vg_name"], lv["lv_name"]
			if p := mapperPath(vg, name); inUse[p] || inUse[realPath(p)] {
				covered[vg] = true // mounted: its filesystem is reported already
			}
			if !strings.HasPrefix(lv["lv_attr"], "t") {
				continue
			}
			covered[vg] = true
			size, okSize := num(lv["lv_size"])
			data, okData := num(lv["data_percent"])
			if !okSize || size <= 0 || !okData {
				continue // inactive pools report no usage
			}
			emit("lvm:"+vg+"/"+name, "lvm:"+vg, size, data)
			if meta, ok := num(lv["metadata_percent"]); ok {
				out = append(out, sample("sentinel_custom_lvm_metadata_percent", meta, "pool", vg+"/"+name))
			}
		}
	}
	for _, r := range vgs.Report {
		for _, vg := range r.VG {
			name := vg["vg_name"]
			size, ok := num(vg["vg_size"])
			free, okFree := num(vg["vg_free"])
			if name == "" || !ok || !okFree || size <= 0 || covered[name] {
				continue
			}
			emit("lvm:"+name, "lvm:"+name, size, 100*(size-free)/size)
		}
	}
	return out, nil // nothing beyond what the disk collector reports is fine
}
