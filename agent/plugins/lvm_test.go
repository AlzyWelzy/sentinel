package plugins

import "testing"

func usedByMount(t *testing.T, vgs, lvs string, inUse map[string]bool) map[string]float64 {
	t.Helper()
	s, err := parseLVM([]byte(vgs), []byte(lvs), inUse)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, x := range s {
		if x.Name == "sentinel_disk_used_percent" {
			got[x.Labels["mountpoint"]] = x.Value
		}
	}
	return got
}

func TestParseLVMProxmox(t *testing.T) {
	vgs := `{"report":[{"vg":[{"vg_name":"pve","vg_size":"799063146496","vg_free":"17179869184"},{"vg_name":"vg_alletra","vg_size":"10445360463872","vg_free":"1044536046387"}]}]}`
	lvs := `{"report":[{"lv":[
		{"vg_name":"pve","lv_name":"data","lv_size":"656800000000","lv_attr":"twi-aotz--","data_percent":"41.50","metadata_percent":"2.10"},
		{"vg_name":"pve","lv_name":"root","lv_size":"103079215104","lv_attr":"-wi-ao----","data_percent":"","metadata_percent":""},
		{"vg_name":"vg_alletra","lv_name":"vm-100-disk-0","lv_size":"1099511627776","lv_attr":"-wi-a-----","data_percent":"","metadata_percent":""}]}]}`
	got := usedByMount(t, vgs, lvs, nil)
	if len(got) != 2 || got["lvm:pve/data"] != 41.5 || got["lvm:vg_alletra"] < 89.9 || got["lvm:vg_alletra"] > 90.1 {
		t.Fatalf("%v", got)
	}
}

func TestParseLVMNothing(t *testing.T) {
	if s, err := parseLVM([]byte(`{"report":[{"vg":[]}]}`), []byte(`{"report":[{"lv":[]}]}`), nil); err != nil || len(s) != 0 {
		t.Fatal(s, err)
	}
}

func TestParseLVMSkipsMountedGroup(t *testing.T) {
	// A standard LVM install (root on LVM, all space handed out) isn't full.
	vgs := `{"report":[{"vg":[{"vg_name":"almalinux","vg_size":"100","vg_free":"0"},{"vg_name":"san","vg_size":"100","vg_free":"40"}]}]}`
	lvs := `{"report":[{"lv":[{"vg_name":"almalinux","lv_name":"root","lv_size":"100","lv_attr":"-wi-ao----"},
		{"vg_name":"san","lv_name":"vm-1-disk-0","lv_size":"60","lv_attr":"-wi-ao----"}]}]}`
	got := usedByMount(t, vgs, lvs, map[string]bool{"/dev/mapper/almalinux-root": true})
	if len(got) != 1 || got["lvm:san"] != 60 {
		t.Fatalf("%v", got)
	}
}

func TestParseLVMDashesInNames(t *testing.T) {
	// device-mapper doubles dashes: vg "data-vg", lv "my-root".
	vgs := `{"report":[{"vg":[{"vg_name":"data-vg","vg_size":"100","vg_free":"0"}]}]}`
	lvs := `{"report":[{"lv":[{"vg_name":"data-vg","lv_name":"my-root","lv_size":"100","lv_attr":"-wi-ao----"}]}]}`
	if got := usedByMount(t, vgs, lvs, map[string]bool{"/dev/mapper/data--vg-my--root": true}); len(got) != 0 {
		t.Fatalf("mounted group with dashes reported: %v", got)
	}
}

func TestParseLVMInactivePoolAndJunk(t *testing.T) {
	// An inactive pool has no data_percent: not "0% used". Garbage sizes
	// are skipped, and percentages stay within 0-100.
	vgs := `{"report":[{"vg":[{"vg_name":"bad","vg_size":"NaN","vg_free":"1"},{"vg_name":"over","vg_size":"100","vg_free":"-50"}]}]}`
	lvs := `{"report":[{"lv":[{"vg_name":"pve","lv_name":"data","lv_size":"100","lv_attr":"twi---tz--","data_percent":"","metadata_percent":""}]}]}`
	got := usedByMount(t, vgs, lvs, nil)
	if _, ok := got["lvm:pve/data"]; ok {
		t.Fatalf("inactive pool reported: %v", got)
	}
	if _, ok := got["lvm:bad"]; ok || got["lvm:over"] != 100 {
		t.Fatalf("%v", got)
	}
}

func TestParseLVMUnreadable(t *testing.T) {
	if _, err := parseLVM([]byte("  Unrecognised field"), []byte("{}"), nil); err == nil {
		t.Fatal("garbage accepted")
	}
}
