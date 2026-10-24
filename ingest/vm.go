package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/example-org/pulsegrid/proto"
)

var (
	metricNameRe = regexp.MustCompile(`^pulsegrid_[a-z0-9_]{1,100}$`)
	labelNameRe  = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,49}$`)
)

// Labels the agent may not set: ingest owns them, because they decide whose
// data a sample is.
var reservedLabels = map[string]bool{"tenant_id": true, "host_id": true}

const (
	maxLabelsPerSample = 10
	maxLabelValueLen   = 200
)

type victoriaMetrics struct {
	baseURL string
	client  *http.Client
}

// toPrometheusText converts a request to the Prometheus text format with
// millisecond timestamps, stamping host_id on every sample. Invalid samples
// are dropped and counted, so one bad metric can't block a whole batch.
func toPrometheusText(req proto.MetricsRequest, hostID string) (body []byte, kept, dropped int) {
	var buf bytes.Buffer
	for _, batch := range req.Batches {
		ts := strconv.FormatInt(batch.TimestampMs, 10)
		for _, s := range batch.Samples {
			if !validSample(s) {
				dropped++
				continue
			}
			buf.WriteString(s.Name)
			buf.WriteString(`{host_id="`)
			buf.WriteString(hostID)
			buf.WriteByte('"')
			for k, v := range s.Labels {
				buf.WriteByte(',')
				buf.WriteString(k)
				buf.WriteString(`="`)
				buf.WriteString(escapeLabelValue(v))
				buf.WriteByte('"')
			}
			buf.WriteString("} ")
			buf.WriteString(strconv.FormatFloat(s.Value, 'g', -1, 64))
			buf.WriteByte(' ')
			buf.WriteString(ts)
			buf.WriteByte('\n')
			kept++
		}
	}
	return buf.Bytes(), kept, dropped
}

func validSample(s proto.Sample) bool {
	if !metricNameRe.MatchString(s.Name) || len(s.Labels) > maxLabelsPerSample {
		return false
	}
	for k, v := range s.Labels {
		if reservedLabels[k] || !labelNameRe.MatchString(k) || len(v) > maxLabelValueLen {
			return false
		}
	}
	return true
}

var labelValueEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func escapeLabelValue(v string) string { return labelValueEscaper.Replace(v) }

// write imports samples under one tenant. extra_label makes VictoriaMetrics
// set tenant_id on every series, overriding anything in the body.
func (vm *victoriaMetrics) write(ctx context.Context, tenantID string, body []byte) error {
	u := vm.baseURL + "/api/v1/import/prometheus?extra_label=" +
		url.QueryEscape("tenant_id="+tenantID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	resp, err := vm.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("victoriametrics import: %s: %s", resp.Status, msg)
	}
	return nil
}
