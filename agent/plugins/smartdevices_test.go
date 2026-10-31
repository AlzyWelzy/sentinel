package plugins

import (
	"reflect"
	"testing"
)

func TestSmartDevicesMegaraid(t *testing.T) {
	got := SmartDevices("/dev/sda:sat,/dev/bus/0:megaraid,1,/dev/bus/0:megaraid,12,/dev/nvme0:nvme")
	want := [][2]string{{"/dev/sda", "sat"}, {"/dev/bus/0", "megaraid,1"}, {"/dev/bus/0", "megaraid,12"}, {"/dev/nvme0", "nvme"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}
