package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/AlzyWelzy/pulsegrid-beyond/agent/plugins"
	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

func TestActions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix commands and file modes; Windows relies on the installer's folder ACLs")
	}
	plugins.AllowUserOwnedForTests()
	dir := t.TempDir()
	ctx := context.Background()

	if r := runAction(ctx, dir, proto.ActionRequest{ID: "1", Name: "restart-nginx"}); r.Status != "refused" {
		t.Fatalf("no actions file should refuse: %+v", r)
	}
	os.WriteFile(filepath.Join(dir, actionsFile), []byte(
		"say-hi = /bin/echo hi\nfail = /bin/sh -c exit\\ 3\nrelative = echo nope\n"), 0o644)
	if r := runAction(ctx, dir, proto.ActionRequest{ID: "2", Name: "say-hi"}); r.Status != "succeeded" || r.Output != "hi" {
		t.Fatalf("%+v", r)
	}
	if r := runAction(ctx, dir, proto.ActionRequest{ID: "3", Name: "relative"}); r.Status != "refused" {
		t.Fatalf("relative command must be refused: %+v", r)
	}
	if r := runAction(ctx, dir, proto.ActionRequest{ID: "4", Name: "rm -rf /"}); r.Status != "refused" || !strings.Contains(r.Output, "isn't allowed") {
		t.Fatalf("%+v", r)
	}
	os.WriteFile(filepath.Join(dir, actionsFile), []byte("x = /bin/false\n"), 0o666)
	os.Chmod(filepath.Join(dir, actionsFile), 0o666)
	if r := runAction(ctx, dir, proto.ActionRequest{ID: "5", Name: "x"}); r.Status != "refused" {
		t.Fatalf("world-writable actions file must be refused: %+v", r)
	}
}

func TestWriteActions(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, actionsFile)
	if err := writeActions(p, map[string]string{"b": "/bin/b", "a": "/bin/a x"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "a = /bin/a x\nb = /bin/b\n") {
		t.Fatalf("%s", b)
	}
	if got := sudoersEscape("/bin/x a,b:c=d"); got != `/bin/x a\,b\:c\=d` {
		t.Fatal(got)
	}
}
