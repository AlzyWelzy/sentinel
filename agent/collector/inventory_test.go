package collector

import (
	"context"
	"testing"
)

func TestParsePackages(t *testing.T) {
	cases := []struct {
		in, sep, name, ver string
	}{
		{"nginx\t1.24.0-2ubuntu7\n", "\t", "nginx", "1.24.0-2ubuntu7"},
		{"musl-1.2.5-r0\n", "apk", "musl", "1.2.5-r0"},
		{"bash-5.2.37 GNU Bourne Again Shell\n", "pkg_info", "bash", "5.2.37"},
		{"git 2.47.0\n", " ", "git", "2.47.0"},
	}
	for _, c := range cases {
		p := parsePackages([]byte(c.in), c.sep)
		if len(p) != 1 || p[0].Name != c.name || p[0].Version != c.ver {
			t.Errorf("%q: %+v", c.in, p)
		}
	}
}

func TestInventoryRuns(t *testing.T) {
	inv := Inventory(context.Background())
	if inv.KernelVersion == "" {
		t.Fatal("no kernel version")
	}
}
