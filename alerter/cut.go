package main

import "unicode/utf8"

// cut shortens s to at most n bytes without splitting a character: services
// refuse invalid UTF-8 (Discord and Telegram with a 400, which would drop the
// alert), and so does Postgres.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
