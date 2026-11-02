package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// errNotFound means the object is gone (deleted outside Terraform).
var errNotFound = errors.New("not found")

// Client calls the Sentinel API with an API token.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
	ua      string
}

func newClient(baseURL, token, version string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 30 * time.Second},
		ua:      "terraform-provider-sentinel/" + version,
	}
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("User-Agent", c.ua)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode == http.StatusNotFound {
		return errNotFound
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, apiDetail(data))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// apiDetail pulls the message out of FastAPI's {"detail": ...}.
func apiDetail(data []byte) string {
	var e struct {
		Detail json.RawMessage `json:"detail"`
	}
	if json.Unmarshal(data, &e) == nil && len(e.Detail) > 0 {
		var s string
		if json.Unmarshal(e.Detail, &s) == nil {
			return s
		}
		var items []struct {
			Loc []any  `json:"loc"`
			Msg string `json:"msg"`
		}
		if json.Unmarshal(e.Detail, &items) == nil {
			var parts []string
			for _, it := range items {
				field := ""
				if n := len(it.Loc); n > 0 {
					field = fmt.Sprint(it.Loc[n-1]) + ": "
				}
				parts = append(parts, field+strings.TrimPrefix(it.Msg, "Value error, "))
			}
			return strings.Join(parts, "; ")
		}
	}
	return strings.TrimSpace(string(data))
}
