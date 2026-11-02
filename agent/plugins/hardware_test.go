package plugins

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

func find(s []proto.Sample, name string, labels ...string) (float64, bool) {
next:
	for _, x := range s {
		if x.Name != name {
			continue
		}
		for i := 0; i+1 < len(labels); i += 2 {
			if x.Labels[labels[i]] != labels[i+1] {
				continue next
			}
		}
		return x.Value, true
	}
	return 0, false
}

func TestParseSmartATA(t *testing.T) {
	out := `{"model_name":"WDC WD40EFRX","smart_status":{"passed":false},"temperature":{"current":41},
"power_on_time":{"hours":31337},"ata_smart_attributes":{"table":[
{"id":5,"raw":{"value":12}},{"id":9,"raw":{"value":31337}},{"id":197,"raw":{"value":3}},{"id":198,"raw":{"value":1}}]}}`
	s, err := parseSmart([]byte(out), "/dev/sda")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]float64{
		"pulsegrid_custom_smart_healthy":               0,
		"pulsegrid_custom_smart_temperature_celsius":   41,
		"pulsegrid_custom_smart_power_on_hours":        31337,
		"pulsegrid_custom_smart_reallocated_sectors":   12,
		"pulsegrid_custom_smart_pending_sectors":       3,
		"pulsegrid_custom_smart_offline_uncorrectable": 1,
	} {
		if v, ok := find(s, name, "device", "sda"); !ok || v != want {
			t.Errorf("%s = %v (%v), want %v", name, v, ok, want)
		}
	}
}

func TestParseSmartNVMeAndMissing(t *testing.T) {
	out := `{"model_name":"Samsung 980","smart_status":{"passed":true},"temperature":{"current":38},
"nvme_smart_health_information_log":{"critical_warning":0,"available_spare":100,"percentage_used":7,"media_errors":0}}`
	s, err := parseSmart([]byte(out), "/dev/nvme0")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := find(s, "pulsegrid_custom_smart_nvme_percentage_used", "device", "nvme0"); v != 7 {
		t.Fatalf("wear: %v", v)
	}
	if v, _ := find(s, "pulsegrid_custom_smart_healthy", "device", "nvme0", "model", "Samsung 980"); v != 1 {
		t.Fatal("healthy")
	}
	_, err = parseSmart([]byte(`{"smartctl":{"messages":[{"string":"/dev/vda: Unable to detect device type"}]}}`), "/dev/vda")
	if err == nil || !strings.Contains(err.Error(), "Unable to detect") {
		t.Fatalf("missing SMART should explain: %v", err)
	}
	if got := SmartDevices("/dev/sda:sat, /dev/nvme0:nvme,"); len(got) != 2 || got[1] != [2]string{"/dev/nvme0", "nvme"} {
		t.Fatalf("%v", got)
	}
	if args := SmartArgs("/usr/sbin/smartctl", "/dev/sda", "sat"); strings.Join(args, " ") != "/usr/sbin/smartctl -j -H -A -i -d sat /dev/sda" {
		t.Fatalf("command must stay as sudoers expects: %v", args)
	}
}

func TestSmartRefusesOddDevices(t *testing.T) {
	_, err := collectSmart(context.Background(), Config{Settings: map[string]string{"smartctl": "/bin/false", "devices": "/dev/sda;rm -rf /:sat"}})
	if err == nil || !strings.Contains(err.Error(), "not a device path") {
		t.Fatalf("%v", err)
	}
}

func TestParseIPMI(t *testing.T) {
	out := `CPU1 Temp,01h,ok,3.1,45 degrees C
FAN1,30h,ok,29.1,5400 RPM
PSU1 Status,60h,cr,10.1,0x02
12V,40h,nc,7.1,11.62 Volts
FAN4,33h,ns,29.4,No Reading
`
	s, err := parseIPMI([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := find(s, "pulsegrid_custom_ipmi_sensor", "sensor", "CPU1 Temp", "unit", "celsius"); v != 45 {
		t.Fatalf("temp %v", v)
	}
	if v, _ := find(s, "pulsegrid_custom_ipmi_sensor", "sensor", "FAN1", "unit", "rpm"); v != 5400 {
		t.Fatalf("fan %v", v)
	}
	if v, ok := find(s, "pulsegrid_custom_ipmi_sensor_ok", "sensor", "PSU1 Status"); !ok || v != 0 {
		t.Fatal("failed PSU must read not ok")
	}
	if v, _ := find(s, "pulsegrid_custom_ipmi_sensor_ok", "sensor", "12V"); v != 0 {
		t.Fatal("non-critical is not ok")
	}
	if _, ok := find(s, "pulsegrid_custom_ipmi_sensor", "sensor", "FAN4"); ok {
		t.Fatal("absent sensors are skipped")
	}
	if _, err := parseIPMI(nil); err == nil {
		t.Fatal("no readings must explain")
	}
}

func TestSNMPSettings(t *testing.T) {
	if _, err := SNMPClient(map[string]string{}); err == nil {
		t.Fatal("address required")
	}
	g, err := SNMPClient(map[string]string{"address": "10.0.0.2", "community": "secret"})
	if err != nil || g.Port != 161 || g.Community != "secret" {
		t.Fatalf("%+v %v", g, err)
	}
	if _, err := SNMPClient(map[string]string{"address": "10.0.0.2:1161", "version": "3"}); err == nil {
		t.Fatal("v3 without user")
	}
	if _, err := SNMPClient(map[string]string{"address": "sw1", "version": "3", "user": "u", "auth_password": "x", "auth_protocol": "rot13"}); err == nil {
		t.Fatal("bad auth protocol")
	}
	if _, err := SNMPClient(map[string]string{"address": "sw1", "version": "3", "user": "u", "auth_password": "authpass1", "priv_password": "privpass1"}); err != nil {
		t.Fatal(err)
	}
	oids, err := CustomOIDs("ups_load=1.3.6.1.2.1.33.1.4.4.1.5.1, temp=.1.3.6.1.4.1.9.9.13.1.3.1.3.1")
	if err != nil || oids["ups_load"] != ".1.3.6.1.2.1.33.1.4.4.1.5.1" {
		t.Fatalf("%v %v", oids, err)
	}
	for _, bad := range []string{"Load=1.3.6", "x=1.3.6.1;drop", "noequals"} {
		if _, err := CustomOIDs(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

// Against a real agent: SNMP_TEST_ADDR=127.0.0.1:1161 (community public).
func TestSNMPLive(t *testing.T) {
	addr := os.Getenv("SNMP_TEST_ADDR")
	if addr == "" {
		t.Skip("set SNMP_TEST_ADDR to test against a real SNMP agent")
	}
	s, err := collectSNMP(context.Background(), Config{Settings: map[string]string{"address": addr, "oids": "processes=1.3.6.1.2.1.25.1.6.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := find(s, "pulsegrid_custom_snmp_uptime_seconds"); !ok || v <= 0 {
		t.Fatalf("uptime: %v %v", v, ok)
	}
	if _, ok := find(s, "pulsegrid_custom_snmp_processes"); !ok {
		t.Fatal("custom oid missing")
	}
	n := 0
	for _, x := range s {
		if x.Name == "pulsegrid_custom_snmp_if_in_bytes_total" {
			n++
		}
	}
	if n == 0 {
		t.Fatal("no interfaces")
	}
	t.Logf("%d samples, %d interfaces", len(s), n)
}
