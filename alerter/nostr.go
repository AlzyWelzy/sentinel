package main

// Nostr direct messages (NIP-04): the alert is encrypted to each recipient
// (ECDH on secp256k1, AES-256-CBC), signed with the sender's key (BIP-340
// Schnorr, NIP-01) and published to the contact's relays over WebSocket.
// It's delivered when any relay accepts it.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/AlzyWelzy/sentinel/proto"
)

const (
	nostrMaxRelays     = 5
	nostrMaxRecipients = 10
	nostrRelayTimeout  = 10 * time.Second
)

type nostrSender struct{ def proto.Notifier }

func (s *nostrSender) send(ctx context.Context, target string, m message) error {
	return s.sendWithConfig(ctx, target, nil, m)
}

func (s *nostrSender) sendWithConfig(ctx context.Context, _ string, cfg map[string]string, m message) error {
	priv, err := nostrKey(cfg["private_key"], "nsec")
	if err != nil {
		return permanent("Nostr sender key: %v", err)
	}
	sk, _ := btcec.PrivKeyFromBytes(priv)
	var recipients [][]byte
	for _, r := range splitList(cfg["recipients"]) {
		pub, err := nostrKey(r, "npub")
		if err != nil {
			return permanent("Nostr recipient %s: %v", cut(r, 20), err)
		}
		recipients = append(recipients, pub)
	}
	if len(recipients) == 0 || len(recipients) > nostrMaxRecipients {
		return permanent("Nostr needs 1 to %d recipients", nostrMaxRecipients)
	}
	var relays []string
	for _, r := range splitList(cfg["relays"]) {
		u, err := url.Parse(r)
		if err != nil || (u.Scheme != "wss" && u.Scheme != "ws") || u.Host == "" {
			return permanent("Nostr relay %q isn't a wss:// address", cut(r, 60))
		}
		relays = append(relays, u.String())
	}
	if len(relays) == 0 || len(relays) > nostrMaxRelays {
		return permanent("Nostr needs 1 to %d relays", nostrMaxRelays)
	}
	vals := alertValues(m)
	text := vals["title"]
	if vals["text"] != "" {
		text += "\n\n" + vals["text"]
	}
	text = cut(text, 4000)

	var events []nostrEvent
	for _, pub := range recipients {
		content, err := nip04Encrypt(sk, pub, text)
		if err != nil {
			return permanent("Nostr: %v", err)
		}
		ev, err := signNostrEvent(sk, 4, [][]string{{"p", hex.EncodeToString(pub)}}, content, time.Now())
		if err != nil {
			return permanent("Nostr: %v", err)
		}
		events = append(events, ev)
	}
	var lastErr error
	for _, ev := range events {
		delivered := false
		for _, relay := range relays {
			if err := publishNostr(ctx, relay, ev); err != nil {
				lastErr = fmt.Errorf("%s: %w", relay, err)
				continue
			}
			delivered = true
		}
		if !delivered {
			return fmt.Errorf("no Nostr relay accepted the message: %v", lastErr)
		}
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// nostrKey reads a 32-byte key given as bech32 (nsec1…/npub1…) or hex.
func nostrKey(s, hrp string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) == 64 {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, errors.New("not hex")
		}
		return b, nil
	}
	got, data, err := bech32.Decode(s)
	if err != nil || got != hrp {
		return nil, fmt.Errorf("expected an %s1… key", hrp)
	}
	b, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil || len(b) != 32 {
		return nil, errors.New("wrong key length")
	}
	return b, nil
}

// nip04Encrypt: AES-256-CBC with the x coordinate of the ECDH point as the
// key, "<base64 ciphertext>?iv=<base64 iv>".
func nip04Encrypt(sk *btcec.PrivateKey, recipient []byte, text string) (string, error) {
	pub, err := btcec.ParsePubKey(append([]byte{0x02}, recipient...))
	if err != nil {
		return "", errors.New("recipient isn't a valid public key")
	}
	key := btcec.GenerateSharedSecret(sk, pub)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	pad := aes.BlockSize - len(text)%aes.BlockSize
	plain := append([]byte(text), bytes.Repeat([]byte{byte(pad)}, pad)...)
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return base64.StdEncoding.EncodeToString(out) + "?iv=" + base64.StdEncoding.EncodeToString(iv), nil
}

type nostrEvent struct {
	ID        string     `json:"id"`
	PubKey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

// nostrJSON encodes like NIP-01's serialization: no HTML escaping.
func nostrJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func signNostrEvent(sk *btcec.PrivateKey, kind int, tags [][]string, content string, at time.Time) (nostrEvent, error) {
	pub := hex.EncodeToString(schnorr.SerializePubKey(sk.PubKey()))
	ev := nostrEvent{PubKey: pub, CreatedAt: at.Unix(), Kind: kind, Tags: tags, Content: content}
	ser, err := nostrJSON([]any{0, ev.PubKey, ev.CreatedAt, ev.Kind, ev.Tags, ev.Content})
	if err != nil {
		return ev, err
	}
	id := sha256.Sum256(ser)
	sig, err := schnorr.Sign(sk, id[:])
	if err != nil {
		return ev, err
	}
	ev.ID, ev.Sig = hex.EncodeToString(id[:]), hex.EncodeToString(sig.Serialize())
	return ev, nil
}

func publishNostr(ctx context.Context, relay string, ev nostrEvent) error {
	ctx, cancel := context.WithTimeout(ctx, nostrRelayTimeout)
	defer cancel()
	dialer := ws.Dialer{Timeout: nostrRelayTimeout}
	conn, _, _, err := dialer.Dial(ctx, relay)
	if err != nil {
		return err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	msg, err := nostrJSON([]any{"EVENT", ev})
	if err != nil {
		return err
	}
	if err := wsutil.WriteClientText(conn, msg); err != nil {
		return err
	}
	for {
		data, err := wsutil.ReadServerText(conn)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return errors.New("the relay didn't answer")
			}
			return err
		}
		var reply []json.RawMessage
		if json.Unmarshal(data, &reply) != nil || len(reply) < 3 {
			continue
		}
		var kind, id string
		_ = json.Unmarshal(reply[0], &kind)
		_ = json.Unmarshal(reply[1], &id)
		if kind != "OK" || id != ev.ID {
			continue
		}
		var accepted bool
		_ = json.Unmarshal(reply[2], &accepted)
		if accepted {
			return nil
		}
		why := ""
		if len(reply) > 3 {
			_ = json.Unmarshal(reply[3], &why)
		}
		return fmt.Errorf("refused: %s", cut(why, 200))
	}
}
