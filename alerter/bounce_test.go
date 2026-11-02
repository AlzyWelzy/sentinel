package main

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

// A mail server that refuses the recipient: the contact is undeliverable,
// and the failure is permanent (no retries).
func TestRejectedRecipientIsUndeliverable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		conn.Write([]byte("220 test ESMTP\r\n"))
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			switch cmd := strings.ToUpper(strings.Fields(line)[0]); cmd {
			case "EHLO", "HELO":
				conn.Write([]byte("250 test\r\n"))
			case "MAIL":
				conn.Write([]byte("250 ok\r\n"))
			case "RCPT":
				conn.Write([]byte("550 5.1.1 no such user\r\n"))
			case "QUIT":
				conn.Write([]byte("221 bye\r\n"))
				return
			default:
				conn.Write([]byte("250 ok\r\n"))
			}
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	e := &emailSender{host: host, port: port, from: "Sentinel <a@example.com>", tlsMode: "none"}
	err = e.sendMail(context.Background(), "gone@example.com", "s", "t", "")
	var bounced *undeliverableError
	if !errors.As(err, &bounced) {
		t.Fatalf("err = %v, want undeliverable", err)
	}
	if !isPermanent(err) {
		t.Fatal("a refused recipient must not be retried")
	}
}
