package apm

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/AlzyWelzy/sentinel/agent/plugins"
)

func TestConfig(t *testing.T) {
	plugins.AllowUserOwnedForTests()
	dir := t.TempDir()
	if _, on, _ := LoadConfig(dir); on {
		t.Fatal("missing file means off")
	}
	os.WriteFile(filepath.Join(dir, ConfigFile), []byte("# local apps\n"), 0o644)
	if c, on, err := LoadConfig(dir); !on || err != nil || c.Listen != "127.0.0.1:4318" {
		t.Fatalf("default listen: %+v %v %v", c, on, err)
	}
	os.WriteFile(filepath.Join(dir, ConfigFile), []byte("listen = nonsense\n"), 0o644)
	if _, _, err := LoadConfig(dir); err == nil {
		t.Fatal("bad listen accepted")
	}
}

func freeAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func TestReceiveAndForward(t *testing.T) {
	var mu sync.Mutex
	var got [][]byte
	fail := true
	forward := func(_ context.Context, ct string, body []byte) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		if fail { // first attempt fails: the batch must stay queued
			fail = false
			return true, io.ErrUnexpectedEOF
		}
		got = append(got, append([]byte(ct+"|"), body...))
		return false, nil
	}
	r := NewReceiver(slog.New(slog.NewTextHandler(io.Discard, nil)), forward)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := freeAddr(t)
	go r.Run(ctx, Config{Listen: addr})
	url := "http://" + addr + "/v1/traces"
	var resp *http.Response
	var err error
	for i := 0; i < 50; i++ {
		if resp, err = http.Post(url, "application/x-protobuf", bytes.NewReader([]byte{1, 2, 3})); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", resp, err)
	}
	if resp, _ := http.Post(url, "text/plain", bytes.NewReader([]byte("x"))); resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("wrong content type accepted: %d", resp.StatusCode)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || string(got[0]) != "application/x-protobuf|\x01\x02\x03" {
		t.Fatalf("forwarded %q", got)
	}
}
