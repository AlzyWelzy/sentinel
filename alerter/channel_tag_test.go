package main

import "testing"

func TestForTags(t *testing.T) {
	acme, globex := "customer-acme", "customer-globex"
	chans := []channel{{ID: "ops"}, {ID: "acme", OnlyTag: &acme}, {ID: "globex", OnlyTag: &globex}}
	ids := func(cs []channel) (out []string) {
		for _, c := range cs {
			out = append(out, c.ID)
		}
		return out
	}
	if got := ids(forTags(chans, []string{"web", "customer-acme"})); len(got) != 2 || got[0] != "ops" || got[1] != "acme" {
		t.Fatalf("acme's server: %v", got)
	}
	if got := ids(forTags(chans, nil)); len(got) != 1 || got[0] != "ops" {
		t.Fatalf("untagged server: %v", got)
	}
	if len(chans) != 3 {
		t.Fatal("forTags must not modify its input")
	}
}
