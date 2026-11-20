package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// openSealed decrypts a device credential sealed by the API
// (app/services/devicesecrets.py): "v1:" + base64url(nonce || ciphertext),
// AES-256-GCM with a key derived from CREDENTIALS_KEY.
func openSealed(credentialsKey, value string, into any) error {
	if credentialsKey == "" {
		return errors.New("CREDENTIALS_KEY is not set")
	}
	raw, ok := strings.CutPrefix(value, "v1:")
	if !ok {
		return errors.New("unknown credential format")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(raw, "="))
	if err != nil || len(data) < 12+16 {
		return errors.New("malformed credential")
	}
	key := sha256.Sum256(append([]byte("sentinel-credentials\x00"), credentialsKey...))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	plain, err := gcm.Open(nil, data[:12], data[12:], nil)
	if err != nil {
		return errors.New("credential can't be decrypted with this CREDENTIALS_KEY")
	}
	return json.Unmarshal(plain, into)
}
