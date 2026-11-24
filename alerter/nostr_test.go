package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/AlzyWelzy/sentinel/proto"
)

func npub(t *testing.T, pub []byte) string {
	conv, err := bech32.ConvertBits(pub, 8, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	s, err := bech32.Encode("npub", conv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func nip04Decrypt(t *testing.T, sk *btcec.PrivateKey, sender []byte, content string) string {
	pub, err := btcec.ParsePubKey(append([]byte{0x02}, sender...))
	if err != nil {
		t.Fatal(err)
	}
	ct, ivPart, _ := strings.Cut(content, "?iv=")
	raw, _ := base64.StdEncoding.DecodeString(ct)
	iv, _ := base64.StdEncoding.DecodeString(ivPart)
	block, _ := aes.NewCipher(btcec.GenerateSharedSecret(sk, pub))
	out := make([]byte, len(raw))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, raw)
	return string(out[:len(out)-int(out[len(out)-1])])
}

// A relay that accepts EVENTs with a valid id and signature.
func fakeRelay(t *testing.T, got chan<- nostrEvent) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
		defer conn.Close()
		data, err := wsutil.ReadClientText(conn)
		if err != nil {
			return
		}
		var msg []json.RawMessage
		var ev nostrEvent
		if json.Unmarshal(data, &msg) != nil || len(msg) != 2 || json.Unmarshal(msg[1], &ev) != nil {
			return
		}
		ser, _ := nostrJSON([]any{0, ev.PubKey, ev.CreatedAt, ev.Kind, ev.Tags, ev.Content})
		id := sha256.Sum256(ser)
		pubB, _ := hex.DecodeString(ev.PubKey)
		sigB, _ := hex.DecodeString(ev.Sig)
		pub, err1 := schnorr.ParsePubKey(pubB)
		sig, err2 := schnorr.ParseSignature(sigB)
		ok := err1 == nil && err2 == nil && hex.EncodeToString(id[:]) == ev.ID && sig.Verify(id[:], pub)
		reply, _ := json.Marshal([]any{"OK", ev.ID, ok, ""})
		_ = wsutil.WriteServerText(conn, reply)
		if ok {
			got <- ev
		}
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

func TestNostrDirectMessage(t *testing.T) {
	sender, _ := btcec.NewPrivateKey()
	recipient, _ := btcec.NewPrivateKey()
	recipientPub := schnorr.SerializePubKey(recipient.PubKey())
	got := make(chan nostrEvent, 1)
	relay := fakeRelay(t, got)

	s := &nostrSender{def: proto.Notifier{Type: "nostr", Label: "Nostr"}}
	cfg := map[string]string{
		"private_key": hex.EncodeToString(sender.Serialize()),
		"recipients":  npub(t, recipientPub),
		"relays":      "wss://127.0.0.1:1, " + relay, // the first refuses: one relay is enough
	}
	m := message{Subject: "[Sentinel] CRITICAL: db-1 disk full", Text: "Disk / is 97% full",
		Event: map[string]any{"type": "alert_firing", "summary": "db-1 disk <full> & more"}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := s.sendWithConfig(ctx, "", cfg, m); err != nil {
		t.Fatal(err)
	}
	ev := <-got
	if ev.Kind != 4 || len(ev.Tags) != 1 || ev.Tags[0][1] != hex.EncodeToString(recipientPub) {
		t.Fatalf("event %+v", ev)
	}
	text := nip04Decrypt(t, recipient, schnorr.SerializePubKey(sender.PubKey()), ev.Content)
	if !strings.Contains(text, "db-1") {
		t.Fatalf("decrypted %q", text)
	}
}

func TestNostrBadSettingsArePermanent(t *testing.T) {
	s := &nostrSender{def: proto.Notifier{Type: "nostr"}}
	err := s.sendWithConfig(context.Background(), "", map[string]string{
		"private_key": "nsec1nope", "recipients": "npub1x", "relays": "wss://r"}, message{Subject: "x"})
	if err == nil || !isPermanent(err) {
		t.Fatalf("err = %v", err)
	}
}

