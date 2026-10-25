package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// logQuery counts a log rule's matching lines per host over its window.
// target is the filter the API built and validated (source, level, text);
// the hosts come from the rule's scope, and the tenant's own VictoriaLogs
// account keeps every other tenant's lines out.
func logQuery(r rule, hosts []host) string {
	ids := make([]string, 0, len(hosts))
	for _, h := range hosts {
		ids = append(ids, h.ID)
	}
	window := r.WindowSeconds
	if window <= 0 {
		window = 300
	}
	return fmt.Sprintf(`_time:%ds {host_id=~"%s"} %s | stats by (host_id) count() hits`,
		window, strings.Join(ids, "|"), r.Target)
}

// logObservations: every host in scope has data (zero lines is a value),
// so an alert resolves once its window is quiet again.
func (e *evaluator) logObservations(ctx context.Context, r rule, hosts []host) (map[string]observation, error) {
	if e.vlogsURL == "" || r.LogsAccount == 0 || strings.TrimSpace(r.Target) == "" {
		return nil, nil
	}
	params := url.Values{
		"query": {logQuery(r, hosts)},
		"time":  {strconv.FormatInt(time.Now().Unix(), 10)},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(e.vlogsURL, "/")+"/select/logsql/stats_query?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("AccountID", strconv.FormatInt(r.LogsAccount, 10))
	req.Header.Set("ProjectID", "0")
	resp, err := e.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return nil, fmt.Errorf("victorialogs stats query: %s: %s", resp.Status, b)
	}
	var body struct {
		Data struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Value  [2]any            `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	counts := map[string]float64{}
	for _, res := range body.Data.Result {
		s, _ := res.Value[1].(string)
		if v, err := strconv.ParseFloat(s, 64); err == nil {
			counts[res.Metric["host_id"]] = v
		}
	}
	out := make(map[string]observation, len(hosts))
	for _, h := range hosts {
		v := counts[h.ID]
		out[h.ID] = observation{HasData: true, Breached: v > r.Threshold, Value: v}
	}
	return out, nil
}
