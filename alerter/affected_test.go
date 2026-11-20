package main

import (
	"fmt"
	"testing"
)

func TestAffectedLine(t *testing.T) {
	if affectedLine(nil) != "" {
		t.Fatal("nothing behind: no line")
	}
	if got := affectedLine([]string{"web-2"}); got != "Behind it, 1 host not reporting either: web-2" {
		t.Fatal(got)
	}
	var many []string
	for i := 12; i >= 1; i-- {
		many = append(many, fmt.Sprintf("srv-%02d", i))
	}
	want := "Behind it, 12 hosts not reporting either: srv-01, srv-02, srv-03, srv-04, srv-05, srv-06, srv-07, srv-08, srv-09, srv-10 and 2 more"
	if got := affectedLine(many); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}
