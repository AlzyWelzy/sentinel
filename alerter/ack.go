package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// ackToken is the token in an alert's one-click acknowledge link: the
// incident id and an HMAC of it, so any message about the incident (the
// first alert, every escalation) can carry a working link without storing a
// secret per incident. api/app/routes/ack.py verifies it with the same key.
func ackToken(secret, incidentID string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("ack:" + incidentID))
	return incidentID + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:18])
}

func ackURL(apiBase, secret, incidentID string) string {
	if apiBase == "" || secret == "" || incidentID == "" {
		return ""
	}
	return strings.TrimRight(apiBase, "/") + "/v1/ack/" + ackToken(secret, incidentID)
}
