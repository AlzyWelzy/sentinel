package main

import (
	"bytes"
	"html/template"
	"strings"
)

// renderHTML builds the HTML part of an alert email from the message's
// event: a coloured banner, the facts, and the two buttons. Plain-text
// messages (verification codes, tests) have no HTML part.
func renderHTML(m message) string {
	if m.Event == nil || m.Event["summary"] == nil {
		return ""
	}
	str := func(k string) string { s, _ := m.Event[k].(string); return s }
	kind := str("type")
	colour, label := "#dc2626", "Alert"
	switch {
	case kind == "alert_resolved":
		colour, label = "#16a34a", "Resolved"
	case kind == "alert_escalation":
		colour, label = "#b91c1c", "Escalated"
	case str("severity") == "warning":
		colour, label = "#d97706", "Warning"
	case str("severity") == "info":
		colour, label = "#2563eb", "Notice"
	}
	data := map[string]any{
		"Colour":    colour,
		"Label":     label,
		"Summary":   str("summary"),
		"Condition": str("condition"),
		"Detail":    str("detail"),
		"Host":      str("hostname"),
		"Rule":      str("rule_name"),
		"URL":       str("url"),
		"AckURL":    extractLink(m.Text, "Acknowledge (stops escalation): "),
		"Resolved":  kind == "alert_resolved",
	}
	var buf bytes.Buffer
	if err := alertEmail.Execute(&buf, data); err != nil {
		return ""
	}
	return buf.String()
}

func extractLink(text, prefix string) string {
	for _, l := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(l, prefix); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

var alertEmail = template.Must(template.New("alert").Parse(`<!doctype html>
<html><body style="margin:0;padding:24px;background:#f1f5f9;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#0f172a">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;margin:0 auto;background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #e2e8f0">
<tr><td style="background:{{.Colour}};padding:14px 24px;color:#ffffff;font-size:13px;font-weight:600;letter-spacing:.04em;text-transform:uppercase">{{.Label}}</td></tr>
<tr><td style="padding:24px">
<h1 style="margin:0 0 8px;font-size:20px;line-height:1.3">{{.Summary}}</h1>
{{if .Condition}}<p style="margin:0 0 16px;font-size:15px;color:#334155">{{.Condition}}</p>{{end}}
{{if .Detail}}<p style="margin:0 0 16px;padding:10px 12px;background:#f8fafc;border-radius:8px;font-family:Menlo,Consolas,monospace;font-size:13px;color:#334155">{{.Detail}}</p>{{end}}
<table role="presentation" cellpadding="0" cellspacing="0" style="font-size:14px;color:#475569;margin-bottom:20px">
{{if .Host}}<tr><td style="padding:2px 16px 2px 0">Server / check</td><td style="color:#0f172a">{{.Host}}</td></tr>{{end}}
{{if .Rule}}<tr><td style="padding:2px 16px 2px 0">Rule</td><td style="color:#0f172a">{{.Rule}}</td></tr>{{end}}
</table>
{{if .URL}}<a href="{{.URL}}" style="display:inline-block;background:#0f172a;color:#ffffff;text-decoration:none;padding:10px 18px;border-radius:8px;font-size:14px;font-weight:600">View incident</a>{{end}}
{{if and .AckURL (not .Resolved)}}<a href="{{.AckURL}}" style="display:inline-block;margin-left:8px;border:1px solid #cbd5e1;color:#0f172a;text-decoration:none;padding:9px 18px;border-radius:8px;font-size:14px;font-weight:600">Acknowledge</a>{{end}}
</td></tr>
<tr><td style="padding:14px 24px;border-top:1px solid #e2e8f0;font-size:12px;color:#94a3b8">Sent by Pulsegrid server monitoring. Manage contacts and alert rules in the console under Monitoring → Servers.</td></tr>
</table></body></html>`))
