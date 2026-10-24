package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDownloadRejectsTamperedBinary(t *testing.T) {
	good := []byte("the real binary")
	sum := sha256.Sum256(good)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("a tampered binary"))
	}))
	defer srv.Close()

	var buf bytes.Buffer
	err := download(context.Background(), srv.Client(), srv.URL, &buf, hex.EncodeToString(sum[:]))
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("tampered download accepted: %v", err)
	}
}

func TestDownloadAcceptsMatchingBinary(t *testing.T) {
	good := []byte("the real binary")
	sum := sha256.Sum256(good)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(good)
	}))
	defer srv.Close()

	var buf bytes.Buffer
	if err := download(context.Background(), srv.Client(), srv.URL, &buf, hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), good) {
		t.Fatal("content changed in transit")
	}
}

func TestMalformedChecksumRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("<html>not found</html>"))
	}))
	defer srv.Close()
	if _, err := fetchChecksum(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Fatal("accepted a non-checksum response")
	}
}
