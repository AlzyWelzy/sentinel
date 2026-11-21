package main

import (
	"strings"
	"testing"
)

func TestGroupDetail(t *testing.T) {
	if groupDetail(nil, 3) != "" {
		t.Fatal("all up has no detail")
	}
	d := groupDetail([]groupMember{{"api", "connection refused"}, {"db", ""}}, 4)
	if d != "2 of 4 down: api (connection refused), db" {
		t.Fatal(d)
	}
	var many []groupMember
	for range 8 {
		many = append(many, groupMember{Name: "x"})
	}
	if d := groupDetail(many, 9); !strings.HasSuffix(d, "and 3 more") {
		t.Fatal(d)
	}
}
