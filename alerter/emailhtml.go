package main

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"time"
)

// renderHTML builds the HTML part of an alert email from the message's
// event: Sentinel's header, a coloured status band with a plain-English
// lead, the facts (times in the organisation's timezone), the detail, and
// big buttons. Table layout and inline styles only (Gmail, Outlook, Apple
// Mail, phones). Plain-text messages (verification codes, tests) have no
// HTML part.
func renderHTML(m message) string {
	if m.HTML != "" {
		return m.HTML
	}
	if m.Event == nil || m.Event["summary"] == nil {
		return ""
	}
	str := func(k string) string { s, _ := m.Event[k].(string); return s }
	kind := str("type")
	tz := str("timezone")
	t := tone{Band: "#fef2f2", BandText: "#991b1b", Badge: "#dc2626"}
	badge := "Critical"
	lead := str("condition")
	switch {
	case kind == "alert_resolved":
		t = tone{"#f0fdf4", "#166534", "#16a34a"}
		badge = "Resolved"
		if lead == "" {
			lead = "This problem has cleared. No action is needed."
		}
	case kind == "alert_escalation":
		t = tone{"#fef2f2", "#7f1d1d", "#7f1d1d"}
		badge = "Escalated"
		// The event went through the outbox as JSON: numbers are floats.
		if step := number(m.Event["step"]); step > 0 {
			badge = fmt.Sprintf("Escalated · step %d", int(step))
		}
		if lead == "" {
			lead = "Nobody has acknowledged this alert yet, so it has been escalated to you."
		}
	case str("severity") == "warning":
		t = tone{"#fffbeb", "#92400e", "#d97706"}
		badge = "Warning"
	case str("severity") == "info":
		t = tone{"#eff6ff", "#1e40af", "#2563eb"}
		badge = "Notice"
	}
	var facts [][2]string
	if h := str("hostname"); h != "" {
		facts = append(facts, [2]string{"Server / check", h})
	}
	if r := str("rule_name"); r != "" {
		facts = append(facts, [2]string{"Rule", r})
	}
	if at, err := time.Parse(time.RFC3339, str("opened_at")); err == nil {
		facts = append(facts, [2]string{"Opened", localTime(at, tz)})
	}
	if d := str("unacked_for"); d != "" {
		if dur, err := time.ParseDuration(d); err == nil {
			facts = append(facts, [2]string{"Unacknowledged for", humanDuration(dur)})
		}
	}
	if at, err := time.Parse(time.RFC3339, str("at")); err == nil {
		label := "Time"
		if kind == "alert_resolved" {
			label = "Cleared"
		}
		facts = append(facts, [2]string{label, localTime(at, tz)})
	}
	data := map[string]any{
		"T":         t,
		"Badge":     badge,
		"Summary":   str("summary"),
		"Lead":      lead,
		"Preheader": strings.TrimSpace(badge + ": " + str("summary")),
		"Detail":    str("detail"),
		"Facts":     facts,
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

type tone struct{ Band, BandText, Badge string }

func number(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	}
	return 0
}

// localTime shows a moment in the organisation's timezone, falling back to
// UTC when the zone is unknown: "Tue 19 Nov 2026, 6:30 PM IST".
func localTime(t time.Time, tz string) string {
	loc, err := time.LoadLocation(tz)
	if err != nil || tz == "" {
		loc = time.UTC
	}
	t = t.In(loc)
	s := t.Format("Mon 2 Jan 2006, 3:04 PM MST")
	// Zones without a common abbreviation print an offset ("+04"); name them.
	if abbr := t.Format("MST"); strings.HasPrefix(abbr, "+") || strings.HasPrefix(abbr, "-") {
		s += " (" + loc.String() + ")"
	}
	return s
}

// humanDuration: "45m", "2h 5m", "3d 4h".
func humanDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	days, hours, mins := int(d.Hours())/24, int(d.Hours())%24, int(d.Minutes())%60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
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
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><title>{{.Summary}}</title></head>
<body style="margin:0;padding:0;background:#eef0f7;-webkit-text-size-adjust:100%;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">{{.Preheader}}&#8199;&#65279;&#847;&#8199;&#65279;&#847;</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eef0f7;">
<tr><td align="center" style="padding:32px 12px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="width:100%;max-width:600px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#0f172a;">
  <tr><td style="padding:0 4px 14px;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
      <td style="font-size:18px;font-weight:800;letter-spacing:-0.02em;color:#0f172a;"><span style="display:inline-block;width:14px;height:14px;border-radius:4px;background:#7c3aed;background-image:linear-gradient(135deg,#7c3aed,#06b6d4);vertical-align:-1px;margin-right:8px;"></span>Sentinel</td>
      <td align="right" style="font-size:12px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.08em;">Monitoring alert</td>
    </tr></table>
  </td></tr>
  <tr><td style="background:#ffffff;border-radius:16px;border:1px solid #e2e8f0;overflow:hidden;box-shadow:0 1px 2px rgba(15,23,42,.04),0 8px 24px rgba(15,23,42,.06);">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
      <tr><td style="height:5px;background:{{.T.Badge}};font-size:0;line-height:0;">&nbsp;</td></tr>
      <tr><td style="background:{{.T.Band}};padding:26px 32px 22px;">
        <span style="display:inline-block;background:{{.T.Badge}};color:#ffffff;font-size:11px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;padding:5px 10px;border-radius:999px;">{{.Badge}}</span>
        <h1 style="margin:14px 0 6px;font-size:22px;line-height:1.3;font-weight:700;color:#0f172a;word-break:break-word;">{{.Summary}}</h1>
        {{if .Lead}}<p style="margin:0;font-size:15px;line-height:1.55;color:{{.T.BandText}};word-break:break-word;">{{.Lead}}</p>{{end}}
      </td></tr>
      {{if .Facts}}<tr><td style="padding:22px 32px 6px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="font-size:14px;">
        {{range .Facts}}<tr>
          <td style="padding:9px 12px 9px 0;border-bottom:1px solid #f1f5f9;color:#64748b;width:38%;vertical-align:top;">{{index . 0}}</td>
          <td style="padding:9px 0;border-bottom:1px solid #f1f5f9;color:#0f172a;font-weight:600;vertical-align:top;word-break:break-word;">{{index . 1}}</td>
        </tr>{{end}}
        </table>
      </td></tr>{{end}}
      {{if .Detail}}<tr><td style="padding:14px 32px 0;">
        <p style="margin:0 0 8px;font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#64748b;">Details</p>
        <div style="padding:12px 14px;background:#f8fafc;border:1px solid #eef0f7;border-radius:10px;font-family:Menlo,Consolas,'Courier New',monospace;font-size:13px;line-height:1.55;color:#334155;white-space:pre-wrap;word-break:break-word;">{{.Detail}}</div>
      </td></tr>{{end}}
      <tr><td style="padding:24px 32px 30px;">
        <table role="presentation" cellpadding="0" cellspacing="0"><tr>
        {{if .URL}}<td style="padding-right:10px;"><a href="{{.URL}}" style="display:inline-block;background:#7c3aed;color:#ffffff;font-size:15px;font-weight:700;text-decoration:none;padding:13px 22px;border-radius:10px;">View incident</a></td>{{end}}
        {{if and .AckURL (not .Resolved)}}<td><a href="{{.AckURL}}" style="display:inline-block;background:#ffffff;color:#0f172a;font-size:15px;font-weight:600;text-decoration:none;padding:12px 21px;border-radius:10px;border:1px solid #cbd5e1;">Acknowledge</a></td>{{end}}
        </tr></table>
      </td></tr>
    </table>
  </td></tr>
  <tr><td style="padding:18px 8px 0;font-size:12px;line-height:1.6;color:#94a3b8;text-align:center;">Sent by Sentinel. Change who gets alerts under Settings › Contacts, and what alerts under Alert rules.{{if and .AckURL (not .Resolved)}} Acknowledging stops further escalation.{{end}}</td></tr>
</table>
</td></tr></table>
</body></html>`))
