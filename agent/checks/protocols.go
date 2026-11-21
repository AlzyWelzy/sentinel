package checks

// Protocol checks: services answered in their own protocol, not just "the
// port is open". Each one speaks just enough of the protocol to know the
// service is serving (a handshake, a ping, a health call) and reports what
// it saw. Every connection goes through dialer(ctx), so probe checks can't
// reach private addresses.

import (
	"bufio"
	"context"
	"crypto/md5" //nolint:gosec // RADIUS defines its password hiding with MD5
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AlzyWelzy/sentinel/proto"
	"github.com/go-sql-driver/mysql"
	"github.com/gosnmp/gosnmp"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

// withPort adds the default port when the target has none.
func withPort(target string, port int) string {
	if _, _, err := net.SplitHostPort(target); err == nil {
		return target
	}
	return net.JoinHostPort(strings.Trim(target, "[]"), strconv.Itoa(port))
}

func useTLS(c proto.Check) *tls.Config {
	if c.Params["tls"] != "true" {
		return nil
	}
	host, _, _ := net.SplitHostPort(c.Target)
	//nolint:gosec // the user asked for it
	return &tls.Config{ServerName: host, InsecureSkipVerify: c.Params["tls_skip_verify"] == "true"}
}

func dialConn(ctx context.Context, c proto.Check, target string) (net.Conn, error) {
	conn, err := dialer(ctx).DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	if cfg := useTLS(c); cfg != nil {
		if cfg.ServerName == "" {
			cfg.ServerName, _, _ = net.SplitHostPort(target)
		}
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return tc, nil
	}
	return conn, nil
}

func deadline(ctx context.Context, conn net.Conn) {
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	}
}

// ── WebSocket ──────────────────────────────────────────────────────────────

// checkWebSocket opens the upgrade handshake and expects 101.
func checkWebSocket(ctx context.Context, c proto.Check) outcome {
	u, err := url.Parse(c.Target)
	if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") || u.Host == "" {
		return outcome{detail: "target must be a ws:// or wss:// URL"}
	}
	scheme, port := "http", 80
	if u.Scheme == "wss" {
		scheme, port = "https", 443
	}
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	hu := *u
	hu.Scheme = scheme
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, hu.String(), nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(key))
	if p := c.Params["subprotocol"]; p != "" {
		req.Header.Set("Sec-WebSocket-Protocol", p)
	}
	conn, err := dialConn(ctx, proto.Check{Params: map[string]string{"tls": strconv.FormatBool(u.Scheme == "wss"),
		"tls_skip_verify": c.Params["tls_skip_verify"]}}, withPort(u.Host, port))
	if err != nil {
		return outcome{detail: cleanErr(err)}
	}
	defer conn.Close()
	deadline(ctx, conn)
	if err := req.Write(conn); err != nil {
		return outcome{detail: cleanErr(err)}
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return outcome{detail: cleanErr(err)}
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return outcome{detail: fmt.Sprintf("HTTP %d instead of 101 Switching Protocols", resp.StatusCode)}
	}
	return outcome{ok: true, detail: "upgraded to WebSocket"}
}

// ── SMTP ───────────────────────────────────────────────────────────────────

// checkSMTP reads the greeting, says EHLO and, with security=starttls,
// upgrades the connection; security=tls connects with TLS from the start.
func checkSMTP(ctx context.Context, c proto.Check) outcome {
	target := withPort(c.Target, 25)
	host, _, _ := net.SplitHostPort(target)
	sec := orDefault(c.Params["security"], "none")
	cc := c
	cc.Params = map[string]string{"tls": strconv.FormatBool(sec == "tls"), "tls_skip_verify": c.Params["tls_skip_verify"]}
	cc.Target = target
	conn, err := dialConn(ctx, cc, target)
	if err != nil {
		return outcome{detail: cleanErr(err)}
	}
	defer conn.Close()
	deadline(ctx, conn)
	cl, err := smtp.NewClient(conn, host)
	if err != nil {
		return outcome{detail: "no SMTP greeting: " + cleanErr(err)}
	}
	defer cl.Close()
	if err := cl.Hello("sentinel-monitor"); err != nil {
		return outcome{detail: "EHLO refused: " + cleanErr(err)}
	}
	if sec == "starttls" {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return outcome{detail: "the server doesn't offer STARTTLS"}
		}
		//nolint:gosec // the user asked for it
		if err := cl.StartTLS(&tls.Config{ServerName: host, InsecureSkipVerify: c.Params["tls_skip_verify"] == "true"}); err != nil {
			return outcome{detail: "STARTTLS failed: " + cleanErr(err)}
		}
	}
	_ = cl.Quit()
	return outcome{ok: true, detail: "SMTP answered (" + sec + ")"}
}

// ── NTP ────────────────────────────────────────────────────────────────────

const ntpEpoch = 2208988800 // seconds from 1900 to 1970

func ntpTime(b []byte) time.Time {
	sec := binary.BigEndian.Uint32(b[0:4])
	frac := binary.BigEndian.Uint32(b[4:8])
	ns := (int64(frac) * 1e9) >> 32
	return time.Unix(int64(sec)-ntpEpoch, ns)
}

// checkNTP asks the server for the time (SNTP) and compares it with ours;
// max_offset_ms and max_stratum bound what counts as healthy.
func checkNTP(ctx context.Context, c proto.Check) outcome {
	conn, err := dialer(ctx).DialContext(ctx, "udp", withPort(c.Target, 123))
	if err != nil {
		return outcome{detail: cleanErr(err)}
	}
	defer conn.Close()
	deadline(ctx, conn)
	req := make([]byte, 48)
	req[0] = 0x23 // version 4, client
	t1 := time.Now()
	if _, err := conn.Write(req); err != nil {
		return outcome{detail: cleanErr(err)}
	}
	resp := make([]byte, 48)
	n, err := conn.Read(resp)
	t4 := time.Now()
	if err != nil {
		return outcome{detail: "no answer: " + cleanErr(err)}
	}
	if n < 48 || resp[0]&0x07 != 4 {
		return outcome{detail: "not an NTP server answer"}
	}
	stratum := int(resp[1])
	if stratum == 0 {
		return outcome{detail: "the server is unsynchronised (kiss-of-death, stratum 0)"}
	}
	t2, t3 := ntpTime(resp[32:40]), ntpTime(resp[40:48])
	offset := (t2.Sub(t1) + t3.Sub(t4)) / 2
	extra := map[string]float64{"sentinel_check_ntp_offset_seconds": offset.Seconds(), "sentinel_check_ntp_stratum": float64(stratum)}
	lat := t4.Sub(t1) - t3.Sub(t2)
	abs := offset
	if abs < 0 {
		abs = -abs
	}
	if max := intParam(c.Params, "max_offset_ms", 0); max > 0 && abs > time.Duration(max)*time.Millisecond {
		return outcome{detail: fmt.Sprintf("clock off by %s (limit %d ms)", offset.Round(time.Millisecond), max), latency: lat, extra: extra}
	}
	if max := intParam(c.Params, "max_stratum", 0); max > 0 && stratum > max {
		return outcome{detail: fmt.Sprintf("stratum %d (limit %d)", stratum, max), latency: lat, extra: extra}
	}
	return outcome{ok: true, detail: fmt.Sprintf("stratum %d, offset %s", stratum, offset.Round(time.Millisecond)), latency: lat, extra: extra}
}

// ── Databases and brokers ──────────────────────────────────────────────────

func checkRedis(ctx context.Context, c proto.Check) outcome {
	opts, err := redis.ParseURL(c.Target)
	if err != nil {
		return outcome{detail: "target must be a redis:// or rediss:// URL"}
	}
	d := dialer(ctx)
	opts.Dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := d.DialContext(ctx, network, addr)
		if err != nil || opts.TLSConfig == nil {
			return conn, err
		}
		cfg := opts.TLSConfig.Clone()
		cfg.InsecureSkipVerify = c.Params["tls_skip_verify"] == "true" //nolint:gosec // the user asked for it
		return tls.Client(conn, cfg), nil
	}
	opts.MaxRetries = -1
	opts.PoolSize = 1
	cl := redis.NewClient(opts)
	defer cl.Close()
	start := time.Now()
	if err := cl.Ping(ctx).Err(); err != nil {
		return outcome{detail: cleanErr(err)}
	}
	return outcome{ok: true, detail: "PONG", latency: time.Since(start)}
}

func checkPostgres(ctx context.Context, c proto.Check) outcome {
	cfg, err := pgx.ParseConfig(c.Target)
	if err != nil {
		return outcome{detail: "target must be a postgres:// URL"}
	}
	cfg.DialFunc = dialer(ctx).DialContext
	start := time.Now()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return outcome{detail: dbErr(err, cfg.Password)}
	}
	defer conn.Close(context.WithoutCancel(ctx))
	return queryOutcome(ctx, c, start, func(q string) (string, error) {
		var v any
		err := conn.QueryRow(ctx, q).Scan(&v)
		return fmt.Sprint(v), err
	})
}

var guardedMySQL sync.Once

func checkMySQL(ctx context.Context, c proto.Check) outcome {
	u, err := url.Parse(c.Target)
	if err != nil || u.Scheme != "mysql" || u.Host == "" {
		return outcome{detail: "target must be a mysql://user:password@host:3306/database URL"}
	}
	cfg := mysql.NewConfig()
	cfg.User = u.User.Username()
	cfg.Passwd, _ = u.User.Password()
	cfg.Addr = withPort(u.Host, 3306)
	cfg.DBName = strings.TrimPrefix(u.Path, "/")
	cfg.Timeout = defaultTimeout
	guardedMySQL.Do(func() {
		mysql.RegisterDialContext("sentinel", func(ctx context.Context, addr string) (net.Conn, error) {
			return dialer(ctx).DialContext(ctx, "tcp", addr)
		})
	})
	cfg.Net = "tcp"
	if pub, _ := ctx.Value(publicOnlyKey{}).(bool); pub {
		cfg.Net = "sentinel"
	}
	if u.Query().Get("tls") == "true" {
		cfg.TLSConfig = "true"
		if c.Params["tls_skip_verify"] == "true" {
			cfg.TLSConfig = "skip-verify"
		}
	}
	conn, err := mysql.NewConnector(cfg)
	if err != nil {
		return outcome{detail: cleanErr(err)}
	}
	db := sql.OpenDB(conn)
	defer db.Close()
	db.SetMaxOpenConns(1)
	start := time.Now()
	if err := db.PingContext(ctx); err != nil {
		return outcome{detail: dbErr(err, cfg.Passwd)}
	}
	return queryOutcome(ctx, c, start, func(q string) (string, error) {
		var v sql.NullString
		err := db.QueryRowContext(ctx, q).Scan(&v)
		return v.String, err
	})
}

// queryOutcome runs the check's query (default SELECT 1) and, with expect,
// compares the first column of the first row.
func queryOutcome(_ context.Context, c proto.Check, start time.Time, run func(string) (string, error)) outcome {
	q := orDefault(c.Params["query"], "SELECT 1")
	got, err := run(q)
	lat := time.Since(start)
	if err != nil {
		return outcome{detail: "query failed: " + cleanErr(err), latency: lat}
	}
	if want, ok := c.Params["expect"]; ok && want != "" && got != want {
		return outcome{detail: fmt.Sprintf("query returned %q, expected %q", truncate(got, 80), truncate(want, 80)), latency: lat}
	}
	return outcome{ok: true, detail: "query returned " + truncate(got, 80), latency: lat}
}

// dbErr never repeats the password, even if a driver puts it in an error.
func dbErr(err error, password string) string {
	s := cleanErr(err)
	if password != "" {
		s = strings.ReplaceAll(s, password, "****")
	}
	return s
}

// checkMongo sends the hello command (no login needed) and expects ok: 1.
func checkMongo(ctx context.Context, c proto.Check) outcome {
	target := strings.TrimPrefix(c.Target, "mongodb://")
	if i := strings.LastIndex(target, "@"); i >= 0 {
		target = target[i+1:]
	}
	target = strings.SplitN(strings.SplitN(target, "/", 2)[0], ",", 2)[0]
	conn, err := dialConn(ctx, c, withPort(target, 27017))
	if err != nil {
		return outcome{detail: cleanErr(err)}
	}
	defer conn.Close()
	deadline(ctx, conn)
	start := time.Now()
	// BSON {hello: 1, $db: "admin"}
	var doc []byte
	doc = append(doc, 0x10)
	doc = append(doc, "hello\x00"...)
	doc = binary.LittleEndian.AppendUint32(doc, 1)
	doc = append(doc, 0x02)
	doc = append(doc, "$db\x00"...)
	doc = binary.LittleEndian.AppendUint32(doc, 6)
	doc = append(doc, "admin\x00"...)
	doc = append(doc, 0x00)
	body := binary.LittleEndian.AppendUint32(nil, uint32(len(doc)+4))
	body = append(body, doc...)
	// OP_MSG: header, flags, section kind 0, document
	msg := binary.LittleEndian.AppendUint32(nil, uint32(16+4+1+len(body)))
	msg = binary.LittleEndian.AppendUint32(msg, 1)    // requestID
	msg = binary.LittleEndian.AppendUint32(msg, 0)    // responseTo
	msg = binary.LittleEndian.AppendUint32(msg, 2013) // OP_MSG
	msg = binary.LittleEndian.AppendUint32(msg, 0)    // flags
	msg = append(msg, 0)
	msg = append(msg, body...)
	if _, err := conn.Write(msg); err != nil {
		return outcome{detail: cleanErr(err)}
	}
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return outcome{detail: "no answer: " + cleanErr(err)}
	}
	size := binary.LittleEndian.Uint32(hdr[0:4])
	if size < 21 || size > 16<<20 || binary.LittleEndian.Uint32(hdr[12:16]) != 2013 {
		return outcome{detail: "not a MongoDB answer"}
	}
	rest := make([]byte, size-16)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return outcome{detail: cleanErr(err)}
	}
	lat := time.Since(start)
	ok, found := bsonOK(rest[5:])
	if !found {
		return outcome{detail: "not a MongoDB answer", latency: lat}
	}
	if !ok {
		return outcome{detail: "MongoDB answered hello with ok: 0", latency: lat}
	}
	return outcome{ok: true, detail: "MongoDB answered", latency: lat}
}

// bsonOK finds the top-level "ok" field of a BSON document.
func bsonOK(doc []byte) (ok, found bool) {
	if len(doc) < 5 {
		return false, false
	}
	n := int(binary.LittleEndian.Uint32(doc))
	if n > len(doc) {
		return false, false
	}
	i := 4
	for i < n-1 {
		t := doc[i]
		i++
		end := i
		for end < n && doc[end] != 0 {
			end++
		}
		if end >= n {
			return false, false
		}
		name := string(doc[i:end])
		i = end + 1
		var size int
		switch t {
		case 0x01, 0x09, 0x11, 0x12: // double, datetime, timestamp, int64
			size = 8
		case 0x10: // int32
			size = 4
		case 0x08: // bool
			size = 1
		case 0x02, 0x0D, 0x0E: // string-like
			if i+4 > n {
				return false, false
			}
			size = 4 + int(binary.LittleEndian.Uint32(doc[i:]))
		case 0x03, 0x04: // document, array
			if i+4 > n {
				return false, false
			}
			size = int(binary.LittleEndian.Uint32(doc[i:]))
		case 0x05: // binary
			if i+4 > n {
				return false, false
			}
			size = 5 + int(binary.LittleEndian.Uint32(doc[i:]))
		case 0x07: // ObjectId
			size = 12
		case 0x0A, 0xFF, 0x7F: // null, min, max
			size = 0
		case 0x13: // decimal128
			size = 16
		default:
			return false, false
		}
		if i+size > n {
			return false, false
		}
		if name == "ok" {
			switch t {
			case 0x01:
				return binary.LittleEndian.Uint64(doc[i:]) == 0x3FF0000000000000, true
			case 0x10:
				return binary.LittleEndian.Uint32(doc[i:]) == 1, true
			case 0x12:
				return binary.LittleEndian.Uint64(doc[i:]) == 1, true
			case 0x08:
				return doc[i] == 1, true
			}
			return false, true
		}
		i += size
	}
	return false, false
}

// checkKafka asks a broker for its API versions (the first thing any client
// does) and expects no error.
func checkKafka(ctx context.Context, c proto.Check) outcome {
	conn, err := dialConn(ctx, c, withPort(c.Target, 9092))
	if err != nil {
		return outcome{detail: cleanErr(err)}
	}
	defer conn.Close()
	deadline(ctx, conn)
	client := "sentinel"
	req := binary.BigEndian.AppendUint16(nil, 18) // ApiVersions
	req = binary.BigEndian.AppendUint16(req, 0)
	req = binary.BigEndian.AppendUint32(req, 7) // correlation id
	req = binary.BigEndian.AppendUint16(req, uint16(len(client)))
	req = append(req, client...)
	start := time.Now()
	if _, err := conn.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(req))), req...)); err != nil {
		return outcome{detail: cleanErr(err)}
	}
	hdr := make([]byte, 10)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return outcome{detail: "no answer: " + cleanErr(err)}
	}
	lat := time.Since(start)
	if binary.BigEndian.Uint32(hdr[4:8]) != 7 {
		return outcome{detail: "not a Kafka answer", latency: lat}
	}
	if code := int16(binary.BigEndian.Uint16(hdr[8:10])); code != 0 {
		return outcome{detail: fmt.Sprintf("broker answered with error %d", code), latency: lat}
	}
	return outcome{ok: true, detail: "broker answered", latency: lat}
}

// ── MQTT ───────────────────────────────────────────────────────────────────

func mqttString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

func mqttPacket(kind byte, body []byte) []byte {
	out := []byte{kind}
	n := len(body)
	for {
		d := byte(n % 128)
		n /= 128
		if n > 0 {
			d |= 0x80
		}
		out = append(out, d)
		if n == 0 {
			break
		}
	}
	return append(out, body...)
}

func mqttRead(r *bufio.Reader) (byte, []byte, error) {
	kind, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	n, mult := 0, 1
	for i := 0; i < 4; i++ {
		d, err := r.ReadByte()
		if err != nil {
			return 0, nil, err
		}
		n += int(d&0x7F) * mult
		mult *= 128
		if d&0x80 == 0 {
			break
		}
	}
	if n > 1<<20 {
		return 0, nil, errors.New("packet too large")
	}
	body := make([]byte, n)
	_, err = io.ReadFull(r, body)
	return kind, body, err
}

// checkMQTT connects (MQTT 3.1.1) and, with a topic, subscribes and waits
// for a message; expect makes the message's content count.
func checkMQTT(ctx context.Context, c proto.Check) outcome {
	target := strings.TrimPrefix(strings.TrimPrefix(c.Target, "mqtt://"), "mqtts://")
	port := 1883
	if c.Params["tls"] == "true" {
		port = 8883
	}
	conn, err := dialConn(ctx, c, withPort(target, port))
	if err != nil {
		return outcome{detail: cleanErr(err)}
	}
	defer conn.Close()
	deadline(ctx, conn)
	id := make([]byte, 6)
	_, _ = rand.Read(id)
	var body []byte
	body = mqttString(body, "MQTT")
	body = append(body, 4) // 3.1.1
	flags := byte(0x02)    // clean session
	user, pass := c.Params["username"], c.Params["password"]
	if user != "" {
		flags |= 0x80
		if pass != "" {
			flags |= 0x40
		}
	}
	body = append(body, flags)
	body = binary.BigEndian.AppendUint16(body, 30)
	body = mqttString(body, fmt.Sprintf("sentinel-%x", id))
	if user != "" {
		body = mqttString(body, user)
		if pass != "" {
			body = mqttString(body, pass)
		}
	}
	start := time.Now()
	if _, err := conn.Write(mqttPacket(0x10, body)); err != nil {
		return outcome{detail: cleanErr(err)}
	}
	r := bufio.NewReader(conn)
	kind, ack, err := mqttRead(r)
	if err != nil {
		return outcome{detail: "no CONNACK: " + cleanErr(err)}
	}
	if kind != 0x20 || len(ack) < 2 {
		return outcome{detail: "not an MQTT broker answer"}
	}
	if ack[1] != 0 {
		reasons := map[byte]string{1: "protocol version refused", 2: "client id refused", 3: "server unavailable", 4: "bad user name or password", 5: "not authorised"}
		return outcome{detail: "broker refused the connection: " + orDefault(reasons[ack[1]], fmt.Sprint(ack[1]))}
	}
	lat := time.Since(start)
	topic := c.Params["topic"]
	if topic == "" {
		_, _ = conn.Write([]byte{0xE0, 0})
		return outcome{ok: true, detail: "broker accepted the connection", latency: lat}
	}
	sub := binary.BigEndian.AppendUint16(nil, 1)
	sub = mqttString(sub, topic)
	sub = append(sub, 0)
	if _, err := conn.Write(mqttPacket(0x82, sub)); err != nil {
		return outcome{detail: cleanErr(err)}
	}
	for {
		kind, pkt, err := mqttRead(r)
		if err != nil {
			return outcome{detail: fmt.Sprintf("no message on %s: %s", topic, cleanErr(err)), latency: lat}
		}
		if kind&0xF0 != 0x30 || len(pkt) < 2 {
			continue
		}
		tl := int(binary.BigEndian.Uint16(pkt))
		off := 2 + tl
		if kind&0x06 != 0 {
			off += 2 // packet id for QoS 1 and 2
		}
		if off > len(pkt) {
			continue
		}
		msg := string(pkt[off:])
		if want := c.Params["expect"]; want != "" && !strings.Contains(msg, want) {
			return outcome{detail: fmt.Sprintf("message on %s doesn't contain %q: %s", topic, want, truncate(msg, 80)), latency: lat}
		}
		_, _ = conn.Write([]byte{0xE0, 0})
		return outcome{ok: true, detail: "message on " + topic + ": " + truncate(msg, 80), latency: lat}
	}
}

// ── gRPC ───────────────────────────────────────────────────────────────────

// checkGRPC calls the standard health service (grpc.health.v1).
func checkGRPC(ctx context.Context, c proto.Check) outcome {
	creds := insecure.NewCredentials()
	if cfg := useTLS(c); cfg != nil {
		creds = credentials.NewTLS(cfg)
	}
	d := dialer(ctx)
	cc, err := grpc.NewClient("passthrough:///"+c.Target,
		grpc.WithTransportCredentials(creds),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", addr)
		}))
	if err != nil {
		return outcome{detail: cleanErr(err)}
	}
	defer cc.Close()
	if md := c.Params["metadata"]; md != "" {
		var m map[string]string
		if json.Unmarshal([]byte(md), &m) == nil {
			ctx = metadata.NewOutgoingContext(ctx, metadata.New(m))
		}
	}
	start := time.Now()
	resp, err := grpc_health_v1.NewHealthClient(cc).Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: c.Params["service"]})
	lat := time.Since(start)
	if err != nil {
		return outcome{detail: cleanErr(err), latency: lat}
	}
	if resp.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
		return outcome{detail: "health: " + resp.GetStatus().String(), latency: lat}
	}
	return outcome{ok: true, detail: "SERVING", latency: lat}
}

// ── SIP and RADIUS ─────────────────────────────────────────────────────────

func checkSIP(ctx context.Context, c proto.Check) outcome {
	target := withPort(c.Target, 5060)
	conn, err := dialer(ctx).DialContext(ctx, "udp", target)
	if err != nil {
		return outcome{detail: cleanErr(err)}
	}
	defer conn.Close()
	deadline(ctx, conn)
	host, _, _ := net.SplitHostPort(target)
	local := conn.LocalAddr().String()
	tag := make([]byte, 6)
	_, _ = rand.Read(tag)
	req := fmt.Sprintf("OPTIONS sip:%s SIP/2.0\r\nVia: SIP/2.0/UDP %s;branch=z9hG4bK%x\r\nMax-Forwards: 70\r\n"+
		"From: <sip:sentinel@%s>;tag=%x\r\nTo: <sip:%s>\r\nCall-ID: %x@sentinel\r\nCSeq: 1 OPTIONS\r\n"+
		"Contact: <sip:sentinel@%s>\r\nAccept: application/sdp\r\nContent-Length: 0\r\n\r\n",
		host, local, tag, local, tag, host, tag, local)
	start := time.Now()
	if _, err := conn.Write([]byte(req)); err != nil {
		return outcome{detail: cleanErr(err)}
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	lat := time.Since(start)
	if err != nil {
		return outcome{detail: "no answer: " + cleanErr(err)}
	}
	line, _, _ := strings.Cut(string(buf[:n]), "\r\n")
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 || parts[0] != "SIP/2.0" {
		return outcome{detail: "not a SIP answer", latency: lat}
	}
	code, _ := strconv.Atoi(parts[1])
	if code < 200 || code >= 300 {
		return outcome{detail: "SIP " + strings.Join(parts[1:], " "), latency: lat}
	}
	return outcome{ok: true, detail: "SIP " + strings.Join(parts[1:], " "), latency: lat}
}

// checkRADIUS sends an Access-Request and expects Access-Accept.
func checkRADIUS(ctx context.Context, c proto.Check) outcome {
	secret, user, pass := c.Params["secret"], c.Params["username"], c.Params["password"]
	if secret == "" || user == "" {
		return outcome{detail: "a RADIUS check needs secret and username"}
	}
	conn, err := dialer(ctx).DialContext(ctx, "udp", withPort(c.Target, 1812))
	if err != nil {
		return outcome{detail: cleanErr(err)}
	}
	defer conn.Close()
	deadline(ctx, conn)
	auth := make([]byte, 16)
	_, _ = rand.Read(auth)
	attr := func(b []byte, t byte, v []byte) []byte { return append(append(b, t, byte(len(v)+2)), v...) }
	// RFC 2865 5.2: the password padded to 16 bytes, XORed with MD5 chains.
	p := []byte(pass)
	if len(p) == 0 || len(p)%16 != 0 {
		p = append(p, make([]byte, 16-len(p)%16)...)
	}
	if len(p) > 128 {
		return outcome{detail: "password longer than 128 bytes"}
	}
	hidden := make([]byte, len(p))
	prev := auth
	for i := 0; i < len(p); i += 16 {
		h := md5.Sum(append([]byte(secret), prev...)) //nolint:gosec // RFC 2865
		for j := 0; j < 16; j++ {
			hidden[i+j] = p[i+j] ^ h[j]
		}
		prev = hidden[i : i+16]
	}
	var attrs []byte
	attrs = attr(attrs, 1, []byte(user))
	attrs = attr(attrs, 2, hidden)
	if v := c.Params["called_station_id"]; v != "" {
		attrs = attr(attrs, 30, []byte(v))
	}
	if v := c.Params["calling_station_id"]; v != "" {
		attrs = attr(attrs, 31, []byte(v))
	}
	pkt := []byte{1, 7}
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(20+len(attrs)))
	pkt = append(append(pkt, auth...), attrs...)
	start := time.Now()
	if _, err := conn.Write(pkt); err != nil {
		return outcome{detail: cleanErr(err)}
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	lat := time.Since(start)
	if err != nil {
		return outcome{detail: "no answer (a wrong secret is silently dropped): " + cleanErr(err)}
	}
	if n < 20 || buf[1] != 7 {
		return outcome{detail: "not a RADIUS answer", latency: lat}
	}
	// The response authenticator proves the server knows the secret.
	h := md5.New() //nolint:gosec // RFC 2865
	h.Write(buf[0:4])
	h.Write(auth)
	h.Write(buf[20:n])
	h.Write([]byte(secret))
	if string(h.Sum(nil)) != string(buf[4:20]) {
		return outcome{detail: "answer not signed with the shared secret", latency: lat}
	}
	switch buf[0] {
	case 2:
		return outcome{ok: true, detail: "Access-Accept", latency: lat}
	case 3:
		return outcome{detail: "Access-Reject", latency: lat}
	case 11:
		return outcome{detail: "Access-Challenge (multi-step login isn't supported)", latency: lat}
	}
	return outcome{detail: fmt.Sprintf("unexpected RADIUS code %d", buf[0]), latency: lat}
}

// ── Game servers ───────────────────────────────────────────────────────────

func checkGame(ctx context.Context, c proto.Check) outcome {
	switch orDefault(c.Params["protocol"], "a2s") {
	case "a2s":
		return checkA2S(ctx, c)
	case "minecraft":
		return checkMinecraft(ctx, c)
	}
	return outcome{detail: "protocol is a2s (Source/Steam games) or minecraft"}
}

// checkA2S is the Source engine query (most Steam games): A2S_INFO, with
// the challenge round trip newer servers require.
func checkA2S(ctx context.Context, c proto.Check) outcome {
	conn, err := dialer(ctx).DialContext(ctx, "udp", withPort(c.Target, 27015))
	if err != nil {
		return outcome{detail: cleanErr(err)}
	}
	defer conn.Close()
	deadline(ctx, conn)
	req := append([]byte{0xFF, 0xFF, 0xFF, 0xFF, 'T'}, "Source Engine Query\x00"...)
	start := time.Now()
	buf := make([]byte, 1400)
	var n int
	for try := 0; try < 3; try++ {
		if _, err := conn.Write(req); err != nil {
			return outcome{detail: cleanErr(err)}
		}
		n, err = conn.Read(buf)
		if err != nil {
			return outcome{detail: "no answer: " + cleanErr(err)}
		}
		if n >= 9 && buf[4] == 'A' { // challenge
			req = append(req[:25:25], buf[5:9]...)
			continue
		}
		break
	}
	lat := time.Since(start)
	if n < 6 || buf[4] != 'I' {
		return outcome{detail: "not a Source query answer", latency: lat}
	}
	b := buf[6:n]
	str := func() string {
		i := 0
		for i < len(b) && b[i] != 0 {
			i++
		}
		s := string(b[:i])
		if i < len(b) {
			b = b[i+1:]
		} else {
			b = nil
		}
		return s
	}
	name, mapName := str(), str()
	str()
	str()
	players, maxPlayers := -1, -1
	if len(b) >= 4 {
		players, maxPlayers = int(b[2]), int(b[3])
	}
	extra := map[string]float64{"sentinel_check_players": float64(players)}
	return outcome{ok: true, detail: fmt.Sprintf("%s on %s, %d/%d players", truncate(name, 60), truncate(mapName, 40), players, maxPlayers), latency: lat, extra: extra}
}

func varint(v int) []byte {
	var out []byte
	u := uint32(v)
	for {
		if u&^0x7F == 0 {
			return append(out, byte(u))
		}
		out = append(out, byte(u&0x7F|0x80))
		u >>= 7
	}
}

func readVarint(r *bufio.Reader) (int, error) {
	var v uint32
	for i := 0; i < 5; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		v |= uint32(b&0x7F) << (7 * i)
		if b&0x80 == 0 {
			return int(v), nil
		}
	}
	return 0, errors.New("varint too long")
}

// checkMinecraft is the Java edition's server list ping.
func checkMinecraft(ctx context.Context, c proto.Check) outcome {
	target := withPort(c.Target, 25565)
	host, portS, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portS)
	conn, err := dialer(ctx).DialContext(ctx, "tcp", target)
	if err != nil {
		return outcome{detail: cleanErr(err)}
	}
	defer conn.Close()
	deadline(ctx, conn)
	hs := append([]byte{0x00}, varint(-1)...)
	hs = append(hs, varint(len(host))...)
	hs = append(hs, host...)
	hs = binary.BigEndian.AppendUint16(hs, uint16(port))
	hs = append(hs, 1)
	pkt := append(varint(len(hs)), hs...)
	pkt = append(pkt, 1, 0) // status request
	start := time.Now()
	if _, err := conn.Write(pkt); err != nil {
		return outcome{detail: cleanErr(err)}
	}
	r := bufio.NewReader(conn)
	if _, err := readVarint(r); err != nil {
		return outcome{detail: "no answer: " + cleanErr(err)}
	}
	if id, err := readVarint(r); err != nil || id != 0 {
		return outcome{detail: "not a Minecraft answer"}
	}
	n, err := readVarint(r)
	if err != nil || n <= 0 || n > 1<<20 {
		return outcome{detail: "not a Minecraft answer"}
	}
	js := make([]byte, n)
	if _, err := io.ReadFull(r, js); err != nil {
		return outcome{detail: cleanErr(err)}
	}
	lat := time.Since(start)
	var st struct {
		Version struct{ Name string }     `json:"version"`
		Players struct{ Online, Max int } `json:"players"`
	}
	if json.Unmarshal(js, &st) != nil {
		return outcome{detail: "not a Minecraft answer", latency: lat}
	}
	return outcome{ok: true, detail: fmt.Sprintf("Minecraft %s, %d/%d players", truncate(st.Version.Name, 30), st.Players.Online, st.Players.Max),
		latency: lat, extra: map[string]float64{"sentinel_check_players": float64(st.Players.Online)}}
}

// ── SNMP ───────────────────────────────────────────────────────────────────

// checkSNMP reads one OID and, with op and expect, compares its value.
func checkSNMP(ctx context.Context, c proto.Check) outcome {
	target := withPort(c.Target, 161)
	host, portS, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portS)
	g := &gosnmp.GoSNMP{
		Target: host, Port: uint16(port), Community: orDefault(c.Params["community"], "public"),
		Version: gosnmp.Version2c, Timeout: defaultTimeout, Retries: 1, Context: ctx,
	}
	if d, ok := ctx.Deadline(); ok {
		g.Timeout = time.Until(d)
	}
	if c.Params["version"] == "1" {
		g.Version = gosnmp.Version1
	}
	if pub, _ := ctx.Value(publicOnlyKey{}).(bool); pub {
		g.Control = dialer(ctx).Control
	}
	if err := g.Connect(); err != nil {
		return outcome{detail: cleanErr(err)}
	}
	defer g.Conn.Close()
	start := time.Now()
	res, err := g.Get([]string{c.Params["oid"]})
	lat := time.Since(start)
	if err != nil {
		return outcome{detail: "no answer: " + cleanErr(err), latency: lat}
	}
	if len(res.Variables) == 0 {
		return outcome{detail: "empty answer", latency: lat}
	}
	v := res.Variables[0]
	switch v.Type {
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView:
		return outcome{detail: "the device has no " + c.Params["oid"], latency: lat}
	}
	var got string
	switch val := v.Value.(type) {
	case []byte:
		got = string(val)
	default:
		got = fmt.Sprint(val)
	}
	if c.Params["op"] != "" {
		if ok, why := compare(got, c.Params["op"], c.Params["expect"]); !ok {
			return outcome{detail: fmt.Sprintf("%s is %s: %s", c.Params["oid"], truncate(got, 80), why), latency: lat}
		}
	}
	return outcome{ok: true, detail: c.Params["oid"] + " = " + truncate(got, 80), latency: lat}
}

// compare checks got against want with op: == != < <= > >= contains
// not_contains. Numbers compare as numbers when both sides parse.
func compare(got, op, want string) (bool, string) {
	g, gerr := strconv.ParseFloat(strings.TrimSpace(got), 64)
	w, werr := strconv.ParseFloat(strings.TrimSpace(want), 64)
	numeric := gerr == nil && werr == nil
	var ok bool
	switch op {
	case "==":
		ok = got == want || (numeric && g == w)
	case "!=":
		ok = got != want && !(numeric && g == w)
	case "contains":
		ok = strings.Contains(got, want)
	case "not_contains":
		ok = !strings.Contains(got, want)
	case "<", "<=", ">", ">=":
		if !numeric {
			return false, fmt.Sprintf("can't compare %q with %s numerically", truncate(got, 40), want)
		}
		ok = map[string]bool{"<": g < w, "<=": g <= w, ">": g > w, ">=": g >= w}[op]
	default:
		return false, "unknown comparison " + op
	}
	if ok {
		return true, ""
	}
	return false, fmt.Sprintf("expected %s %s", op, truncate(want, 40))
}

// ── Docker container and system service (on the agent's own server) ────────

// checkDocker asks the Docker socket about one container: up means running
// and, if it has a health check, healthy.
func checkDocker(ctx context.Context, c proto.Check) outcome {
	sock := orDefault(c.Params["socket"], "/var/run/docker.sock")
	cl := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/"+url.PathEscape(c.Target)+"/json", nil)
	resp, err := cl.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			return outcome{detail: "the agent can't read " + sock + ": add its user to the docker group"}
		}
		return outcome{detail: cleanErr(err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return outcome{detail: "no container named " + c.Target}
	}
	if resp.StatusCode != http.StatusOK {
		return outcome{detail: fmt.Sprintf("Docker answered HTTP %d", resp.StatusCode)}
	}
	var info struct {
		State struct {
			Status     string
			Running    bool
			Restarting bool
			ExitCode   int
			Health     *struct{ Status string }
		}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(&info); err != nil {
		return outcome{detail: "unreadable answer from Docker"}
	}
	s := info.State
	switch {
	case s.Restarting:
		return outcome{detail: "restarting"}
	case !s.Running:
		return outcome{detail: fmt.Sprintf("%s (exit code %d)", s.Status, s.ExitCode)}
	case s.Health != nil && s.Health.Status == "unhealthy":
		return outcome{detail: "running but unhealthy"}
	case s.Health != nil && s.Health.Status == "starting":
		return outcome{ok: true, detail: "running, health check starting"}
	case s.Health != nil:
		return outcome{ok: true, detail: "running, " + s.Health.Status}
	}
	return outcome{ok: true, detail: "running"}
}

var serviceName = regexp.MustCompile(`^[A-Za-z0-9@._:\\-]{1,128}$`)

// checkService asks the service manager whether one service is running.
// It runs a fixed, read-only query (systemctl is-active, sc query, service
// status); the name is checked so it can't become an option.
func checkService(ctx context.Context, c proto.Check) outcome {
	name := c.Target
	if !serviceName.MatchString(name) || strings.HasPrefix(name, "-") {
		return outcome{detail: "not a service name"}
	}
	var out []byte
	var err error
	switch runtime.GOOS {
	case "linux":
		out, err = exec.CommandContext(ctx, "systemctl", "is-active", "--", name).Output()
		state := strings.TrimSpace(string(out))
		if state == "active" {
			return outcome{ok: true, detail: "active"}
		}
		if state == "" && err != nil {
			return outcome{detail: "systemctl: " + cleanErr(err)}
		}
		return outcome{detail: state}
	case "windows":
		out, err = exec.CommandContext(ctx, "sc", "query", name).Output()
		s := string(out)
		if strings.Contains(s, "RUNNING") {
			return outcome{ok: true, detail: "running"}
		}
		if err != nil && !strings.Contains(s, "STATE") {
			return outcome{detail: "no service named " + name}
		}
		for _, l := range strings.Split(s, "\n") {
			if strings.Contains(l, "STATE") {
				return outcome{detail: strings.TrimSpace(l)}
			}
		}
		return outcome{detail: "not running"}
	default: // the BSDs
		err = exec.CommandContext(ctx, "service", name, "status").Run()
		if err == nil {
			return outcome{ok: true, detail: "running"}
		}
		return outcome{detail: "not running"}
	}
}
