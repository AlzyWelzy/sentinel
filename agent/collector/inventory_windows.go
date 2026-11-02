package collector

import (
	"context"
	"sort"

	"golang.org/x/sys/windows/registry"

	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

// windowsPackages reads installed programs from the Uninstall registry keys
// (what "Apps & features" lists), both 64- and 32-bit views.
func windowsPackages(context.Context) []proto.Package {
	seen := map[string]bool{}
	var out []proto.Package
	for _, path := range []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS|registry.READ)
		if err != nil {
			continue
		}
		subs, _ := k.ReadSubKeyNames(-1)
		for _, s := range subs {
			sk, err := registry.OpenKey(k, s, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			name, _, err := sk.GetStringValue("DisplayName")
			ver, _, _ := sk.GetStringValue("DisplayVersion")
			sk.Close()
			if err != nil || name == "" || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, proto.Package{Name: name, Version: ver})
			if len(out) >= maxPackages {
				break
			}
		}
		k.Close()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
