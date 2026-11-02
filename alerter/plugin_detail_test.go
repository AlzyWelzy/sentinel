package main

import "testing"

func TestDescribePluginNamesFailingPlugins(t *testing.T) {
	r := rule{Kind: "plugin_down", Name: "A plugin stopped collecting"}
	subject, _ := describe(r, host{Hostname: "cloud9"}, observation{Plugins: "ipmi, smart"}, false)
	if subject != "Plugin ipmi, smart is failing on cloud9" {
		t.Fatalf("subject %q", subject)
	}
	subject, _ = describe(r, host{Hostname: "cloud9"}, observation{}, false)
	if subject != "A plugin is failing on cloud9" {
		t.Fatalf("subject %q", subject)
	}
}
