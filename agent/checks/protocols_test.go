package checks

import (
	"bufio"
	"context"
	"crypto/md5" //nolint:gosec // RADIUS test
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AlzyWelzy/sentinel/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func check(t *testing.T, typ, target string, params map[string]string) proto.CheckResult {
	t.Helper()
	return runOne(t, NewRunner("test"), proto.Check{ID: typ, Type: typ, Target: target, Params: params})
}

func wantUp(t *testing.T, res proto.CheckResult) {
	t.Helper()
	if !res.OK {
		t.Fatalf("reported down: %s", res.Detail)
	}
}

func wantDown(t *testing.T, res proto.CheckResult, contains string) {
	t.Helper()
	if res.OK {
		t.Fatalf("reported up: %s", res.Detail)
	}
	if !strings.Contains(res.Detail, contains) {
		t.Fatalf("detail %q doesn't mention %q", res.Detail, contains)
	}
}

// tcpServer answers each connection with handle.
func tcpServer(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				handle(c)
			}()
		}
	}()
	return ln.Addr().String()
}

func udpServer(t *testing.T, handle func(req []byte) []byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if out := handle(append([]byte(nil), buf[:n]...)); out != nil {
				_, _ = pc.WriteTo(out, addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

func TestJSONPathAndCompare(t *testing.T) {
	var doc any
	_ = json.Unmarshal([]byte(`{"status":"ok","data":{"items":[{"n":3},{"n":7.5}],"on":true,"none":null}}`), &doc)
	for path, want := range map[string]string{
		"status": "ok", "$.status": "ok", "data.items[1].n": "7.5", "data.items[-1].n": "7.5",
		"data.on": "true", "data.none": "null", "data.items[0]": `{"n":3}`,
	} {
		got, err := jsonPath(doc, path)
		if err != nil || got != want {
			t.Errorf("%s: got %q, %v; want %q", path, got, err, want)
		}
	}
	for _, path := range []string{"missing", "data.items[5]", "status.x", "data.items[x]"} {
		if _, err := jsonPath(doc, path); err == nil {
			t.Errorf("%s: expected an error", path)
		}
	}
	cases := []struct {
		got, op, want string
		ok            bool
	}{
		{"10", ">", "9", true}, {"10", "<", "9", false}, {"1.0", "==", "1", true}, {"abc", "contains", "b", true},
		{"abc", "not_contains", "b", false}, {"abc", ">", "1", false}, {"x", "!=", "y", true}, {"x", "~", "y", false},
	}
	for _, c := range cases {
		if ok, _ := compare(c.got, c.op, c.want); ok != c.ok {
			t.Errorf("%s %s %s: got %v", c.got, c.op, c.want, ok)
		}
	}
}

func TestHTTPJSONHeadersAuthInvert(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, _ := r.BasicAuth(); r.Header.Get("X-Team") != "ops" && (u != "a" || p != "b") {
			http.Error(w, "no", 401)
			return
		}
		if r.Method == http.MethodPut {
			b, _ := io.ReadAll(r.Body)
			if r.Header.Get("Content-Type") != "application/json" || string(b) != `{"x":1}` {
				http.Error(w, "bad body", 400)
				return
			}
		}
		_, _ = w.Write([]byte(`{"health":{"db":"UP","queue":12}}`))
	}))
	defer srv.Close()
	wantUp(t, check(t, "http", srv.URL, map[string]string{"basic_user": "a", "basic_password": "b", "json_path": "health.db", "json_expect": "UP"}))
	wantUp(t, check(t, "http", srv.URL, map[string]string{"headers": `{"X-Team":"ops"}`, "json_path": "health.queue", "json_op": "<", "json_expect": "100"}))
	wantUp(t, check(t, "http", srv.URL, map[string]string{"headers": `{"X-Team":"ops"}`, "method": "PUT", "body": `{"x":1}`}))
	wantDown(t, check(t, "http", srv.URL, map[string]string{"headers": `{"X-Team":"ops"}`, "json_path": "health.queue", "json_op": "<", "json_expect": "5"}), "health.queue is 12")
	wantDown(t, check(t, "http", srv.URL, nil), "HTTP 401")
	wantDown(t, check(t, "http", srv.URL, map[string]string{"headers": `nope`}), "headers must be")
	wantUp(t, check(t, "http", srv.URL, map[string]string{"invert": "true"}))
	wantDown(t, check(t, "http", srv.URL, map[string]string{"basic_user": "a", "basic_password": "b", "invert": "true"}), "expected down")
	wantUp(t, check(t, "http", srv.URL, map[string]string{"basic_user": "a", "basic_password": "b", "keyword": "up", "keyword_case_insensitive": "true"}))
}

func TestHTTPMaxRedirects(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/again", http.StatusFound)
	}))
	defer srv.Close()
	wantDown(t, check(t, "http", srv.URL, map[string]string{"max_redirects": "3"}), "redirects")
}

func TestWebSocket(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" || r.Header.Get("Sec-WebSocket-Key") == "" {
			http.Error(w, "no", 400)
			return
		}
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	defer srv.Close()
	wantUp(t, check(t, "websocket", "ws"+strings.TrimPrefix(srv.URL, "http"), nil))
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer plain.Close()
	wantDown(t, check(t, "websocket", "ws"+strings.TrimPrefix(plain.URL, "http"), nil), "HTTP 200")
	wantDown(t, check(t, "websocket", plain.URL, nil), "ws://")
}

func TestSMTP(t *testing.T) {
	addr := tcpServer(t, func(c net.Conn) {
		r := bufio.NewReader(c)
		fmt.Fprint(c, "220 mail ready\r\n")
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(l, "EHLO"):
				fmt.Fprint(c, "250-mail\r\n250 SIZE 1000\r\n")
			case strings.HasPrefix(l, "QUIT"):
				fmt.Fprint(c, "221 bye\r\n")
				return
			default:
				fmt.Fprint(c, "502 no\r\n")
			}
		}
	})
	wantUp(t, check(t, "smtp", addr, nil))
	wantDown(t, check(t, "smtp", addr, map[string]string{"security": "starttls"}), "STARTTLS")
}

func TestNTP(t *testing.T) {
	var stratum atomic.Int32
	stratum.Store(2)
	addr := udpServer(t, func(req []byte) []byte {
		out := make([]byte, 48)
		out[0] = 0x24 // version 4, server
		out[1] = byte(stratum.Load())
		now := time.Now().Add(2 * time.Second)
		sec := uint32(now.Unix() + ntpEpoch)
		frac := uint32((uint64(now.Nanosecond()) << 32) / 1e9)
		for _, off := range []int{32, 40} {
			binary.BigEndian.PutUint32(out[off:], sec)
			binary.BigEndian.PutUint32(out[off+4:], frac)
		}
		return out
	})
	wantUp(t, check(t, "ntp", addr, nil))
	wantDown(t, check(t, "ntp", addr, map[string]string{"max_offset_ms": "500"}), "clock off")
	wantDown(t, check(t, "ntp", addr, map[string]string{"max_stratum": "1"}), "stratum 2")
	stratum.Store(0)
	wantDown(t, check(t, "ntp", addr, nil), "unsynchronised")
}

func TestMQTT(t *testing.T) {
	addr := tcpServer(t, func(c net.Conn) {
		r := bufio.NewReader(c)
		kind, body, err := mqttRead(r)
		if err != nil || kind != 0x10 {
			return
		}
		code := byte(0)
		if body[7]&0x80 != 0 && !strings.Contains(string(body), "secret") {
			code = 4
		}
		_, _ = c.Write([]byte{0x20, 2, 0, code})
		kind, _, err = mqttRead(r)
		if err != nil || kind != 0x82 {
			return
		}
		_, _ = c.Write([]byte{0x90, 3, 0, 1, 0})
		var pub []byte
		pub = mqttString(pub, "plant/status")
		pub = append(pub, "running"...)
		_, _ = c.Write(mqttPacket(0x30, pub))
	})
	wantUp(t, check(t, "mqtt", addr, nil))
	wantUp(t, check(t, "mqtt", addr, map[string]string{"topic": "plant/status", "expect": "run"}))
	wantDown(t, check(t, "mqtt", addr, map[string]string{"topic": "plant/status", "expect": "stopped"}), "doesn't contain")
	wantUp(t, check(t, "mqtt", addr, map[string]string{"username": "u", "password": "secret"}))
	wantDown(t, check(t, "mqtt", addr, map[string]string{"username": "u", "password": "wrong"}), "bad user name")
}

func TestKafka(t *testing.T) {
	addr := tcpServer(t, func(c net.Conn) {
		hdr := make([]byte, 4)
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		req := make([]byte, binary.BigEndian.Uint32(hdr))
		if _, err := io.ReadFull(c, req); err != nil {
			return
		}
		out := binary.BigEndian.AppendUint32(nil, 6)
		out = append(out, req[4:8]...)
		out = append(out, 0, 0)
		_, _ = c.Write(out)
	})
	wantUp(t, check(t, "kafka", addr, nil))
	junk := tcpServer(t, func(c net.Conn) { _, _ = c.Write([]byte("HTTP/1.1 400 Bad\r\n\r\n")) })
	wantDown(t, check(t, "kafka", junk, nil), "not a Kafka")
}

func TestMongo(t *testing.T) {
	answer := func(ok float64) func(net.Conn) {
		return func(c net.Conn) {
			hdr := make([]byte, 16)
			if _, err := io.ReadFull(c, hdr); err != nil {
				return
			}
			_, _ = io.ReadFull(c, make([]byte, binary.LittleEndian.Uint32(hdr)-16))
			var doc []byte
			doc = append(doc, 0x08)
			doc = append(doc, "isWritablePrimary\x00"...)
			doc = append(doc, 1)
			doc = append(doc, 0x01)
			doc = append(doc, "ok\x00"...)
			bits := uint64(0)
			if ok == 1 {
				bits = 0x3FF0000000000000
			}
			doc = binary.LittleEndian.AppendUint64(doc, bits)
			doc = append(doc, 0)
			body := append(binary.LittleEndian.AppendUint32(nil, uint32(len(doc)+4)), doc...)
			msg := binary.LittleEndian.AppendUint32(nil, uint32(16+5+len(body)))
			msg = binary.LittleEndian.AppendUint32(msg, 9)
			msg = binary.LittleEndian.AppendUint32(msg, 1)
			msg = binary.LittleEndian.AppendUint32(msg, 2013)
			msg = append(msg, 0, 0, 0, 0, 0)
			_, _ = c.Write(append(msg, body...))
		}
	}
	wantUp(t, check(t, "mongodb", "mongodb://user:pw@"+tcpServer(t, answer(1))+"/app", nil))
	wantDown(t, check(t, "mongodb", tcpServer(t, answer(0)), nil), "ok: 0")
}

func TestGRPC(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	hs := health.NewServer()
	hs.SetServingStatus("orders", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	grpc_health_v1.RegisterHealthServer(s, hs)
	go func() { _ = s.Serve(ln) }()
	defer s.Stop()
	wantUp(t, check(t, "grpc", ln.Addr().String(), nil))
	wantDown(t, check(t, "grpc", ln.Addr().String(), map[string]string{"service": "orders"}), "NOT_SERVING")
}

func TestSIP(t *testing.T) {
	addr := udpServer(t, func(req []byte) []byte {
		if !strings.HasPrefix(string(req), "OPTIONS sip:") {
			return nil
		}
		return []byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n")
	})
	wantUp(t, check(t, "sip", addr, nil))
	busy := udpServer(t, func([]byte) []byte { return []byte("SIP/2.0 503 Service Unavailable\r\n\r\n") })
	wantDown(t, check(t, "sip", busy, nil), "503")
}

func TestRADIUS(t *testing.T) {
	const secret = "s3cret"
	addr := udpServer(t, func(req []byte) []byte {
		// Recover the password to decide.
		attrs := req[20:]
		var user, hidden []byte
		for len(attrs) >= 2 {
			t, l := attrs[0], int(attrs[1])
			if t == 1 {
				user = attrs[2:l]
			} else if t == 2 {
				hidden = attrs[2:l]
			}
			attrs = attrs[l:]
		}
		h := md5.Sum(append([]byte(secret), req[4:20]...)) //nolint:gosec // test
		pass := make([]byte, 16)
		for i := range pass {
			pass[i] = hidden[i] ^ h[i]
		}
		code := byte(3)
		if string(user) == "probe" && strings.TrimRight(string(pass), "\x00") == "pw" {
			code = 2
		}
		out := []byte{code, req[1], 0, 20}
		sum := md5.Sum(append(append(out[:4:4], req[4:20]...), []byte(secret)...)) //nolint:gosec // test
		return append(out, sum[:]...)
	})
	wantUp(t, check(t, "radius", addr, map[string]string{"secret": secret, "username": "probe", "password": "pw"}))
	wantDown(t, check(t, "radius", addr, map[string]string{"secret": secret, "username": "probe", "password": "no"}), "Access-Reject")
	wantDown(t, check(t, "radius", addr, map[string]string{"secret": "other", "username": "probe", "password": "pw"}), "not signed")
}

func TestGameServers(t *testing.T) {
	a2s := udpServer(t, func(req []byte) []byte {
		if len(req) == 25 { // first try: ask for the challenge
			return []byte{0xFF, 0xFF, 0xFF, 0xFF, 'A', 1, 2, 3, 4}
		}
		out := []byte{0xFF, 0xFF, 0xFF, 0xFF, 'I', 17}
		out = append(out, "Arena\x00de_dust\x00cs\x00Counter\x00"...)
		return append(out, 10, 0, 7, 16)
	})
	res := check(t, "game", a2s, nil)
	wantUp(t, res)
	if !strings.Contains(res.Detail, "7/16") {
		t.Fatalf("detail %q", res.Detail)
	}
	mc := tcpServer(t, func(c net.Conn) {
		r := bufio.NewReader(c)
		for i := 0; i < 2; i++ {
			n, err := readVarint(r)
			if err != nil {
				return
			}
			_, _ = io.ReadFull(r, make([]byte, n))
		}
		js := `{"version":{"name":"1.21"},"players":{"online":3,"max":20}}`
		body := append([]byte{0}, varint(len(js))...)
		body = append(body, js...)
		_, _ = c.Write(append(varint(len(body)), body...))
	})
	res = check(t, "game", mc, map[string]string{"protocol": "minecraft"})
	wantUp(t, res)
	if !strings.Contains(res.Detail, "3/20") {
		t.Fatalf("detail %q", res.Detail)
	}
}

func TestDocker(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("no unix sockets")
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/web/json":
			_, _ = w.Write([]byte(`{"State":{"Status":"running","Running":true,"Health":{"Status":"healthy"}}}`))
		case "/containers/sick/json":
			_, _ = w.Write([]byte(`{"State":{"Status":"running","Running":true,"Health":{"Status":"unhealthy"}}}`))
		case "/containers/gone/json":
			_, _ = w.Write([]byte(`{"State":{"Status":"exited","Running":false,"ExitCode":137}}`))
		default:
			http.NotFound(w, r)
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	p := map[string]string{"socket": sock}
	wantUp(t, check(t, "docker", "web", p))
	wantDown(t, check(t, "docker", "sick", p), "unhealthy")
	wantDown(t, check(t, "docker", "gone", p), "exit code 137")
	wantDown(t, check(t, "docker", "nope", p), "no container")
}

func TestServiceNameIsNotAnOption(t *testing.T) {
	wantDown(t, check(t, "service", "--version", nil), "not a service")
	wantDown(t, check(t, "service", "a b", nil), "not a service")
}

// The dev stack's Redis and Postgres, when they're running.
func TestRealDatabases(t *testing.T) {
	if os.Getenv("SENTINEL_DEV_DBS") == "" {
		t.Skip("set SENTINEL_DEV_DBS=1 with the dev stack up")
	}
	wantUp(t, check(t, "redis", "redis://127.0.0.1:6389/0", nil))
	wantUp(t, check(t, "postgres", os.Getenv("SENTINEL_DEV_PG"), map[string]string{"query": "SELECT 41+1", "expect": "42"}))
	wantDown(t, check(t, "postgres", "postgres://nobody:hunter2@127.0.0.1:5442/x?connect_timeout=3", nil), "")
	res := check(t, "postgres", "postgres://nobody:hunter2@127.0.0.1:5442/x", nil)
	if strings.Contains(res.Detail, "hunter2") {
		t.Fatal("password in detail")
	}
	_ = context.Background
}
