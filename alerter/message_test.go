package main

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"
)

// A log alert can quote a long line, and names can be long and non-ASCII:
// every line of the message must stay under SMTP's 998-byte limit, and both
// the subject and the body must come back exactly as written.
func TestBuildMessageKeepsLinesShort(t *testing.T) {
	subject := "[Sentinel] FIRING: " + strings.Repeat("Диск заполнен 🚨 ", 40)
	text := "Matched line:\n" + strings.Repeat(`{"level":"error","msg":"x"} `, 300) + "\nend"
	html := "<p>" + strings.Repeat("é", 3000) + "</p>"
	raw := buildMessage("alerts@sentinel.example", "ops@example.com", subject, text, html, time.Unix(0, 0)).Bytes()

	for i, line := range bytes.Split(raw, []byte("\r\n")) {
		if len(line) > 998 {
			t.Fatalf("line %d is %d bytes", i, len(line))
		}
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	got, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil || got != subject {
		t.Fatalf("subject came back as %q (%v)", got, err)
	}
	_, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	r := multipart.NewReader(msg.Body, params["boundary"])
	for _, want := range []string{text, html} {
		p, err := r.NextPart()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(p) // NextPart decodes quoted-printable itself
		if strings.ReplaceAll(string(b), "\r\n", "\n") != want {
			t.Fatalf("part came back changed (%d bytes, want %d)", len(b), len(want))
		}
	}
}
