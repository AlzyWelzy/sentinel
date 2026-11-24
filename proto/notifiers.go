package proto

import (
	_ "embed"
	"encoding/json"
)

// NotifiersJSON is the notification provider catalog: each provider's form
// fields and the one HTTP request that delivers an alert. The alerter sends
// from it (alerter/providers.go) and the API validates contacts against a
// copy of it (api/app/data/notifiers.json; a test keeps the two equal).
//
//go:embed notifiers.json
var NotifiersJSON []byte

type NotifierField struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Hint     string `json:"hint,omitempty"`
	Secret   bool   `json:"secret,omitempty"`
	Required bool   `json:"required,omitempty"`
	URL      bool   `json:"url,omitempty"` // a URL: http(s) only, public addresses only
	// A URL field that must point at the service itself (a webhook URL the
	// service issued): the host must be one of these, or end with one that
	// starts with a dot.
	Hosts   []string   `json:"hosts,omitempty"`
	Pattern string     `json:"pattern,omitempty"`
	Default string     `json:"default,omitempty"`
	Options [][]string `json:"options,omitempty"`
}

type NotifierRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	// json (Body is a JSON tree), form (a flat map), text (a string), or
	// query (a flat map added to the URL, no body).
	Format    string    `json:"format"`
	Body      any       `json:"body,omitempty"`
	BasicAuth [2]string `json:"basic_auth,omitempty"`
	// Services that answer 200 with an error inside: the JSON path whose
	// value must be one of OKValues.
	OKPath   string   `json:"ok_path,omitempty"`
	OKValues []string `json:"ok_values,omitempty"`
	// Services that want an OAuth 2.0 access token first (client
	// credentials): the token is fetched, cached until it expires and sent
	// as a Bearer token. Fields are templates like the rest.
	OAuth *NotifierOAuth `json:"oauth,omitempty"`
}

type NotifierOAuth struct {
	TokenURL     string `json:"token_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Scope        string `json:"scope,omitempty"`
}

type Notifier struct {
	Type    string          `json:"type"`
	Label   string          `json:"label"`
	Group   string          `json:"group"`
	Docs    string          `json:"docs,omitempty"`
	Fields  []NotifierField `json:"fields"`
	Request NotifierRequest `json:"request"`
}

// Notifiers parses the catalog.
func Notifiers() ([]Notifier, error) {
	var out []Notifier
	err := json.Unmarshal(NotifiersJSON, &out)
	return out, err
}
