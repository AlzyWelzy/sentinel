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
// millisecond timestamps, grouped by the tenant each sample belongs to.
// Invalid samples are dropped and counted, so one bad metric can't block a
// whole batch.
//
// Ordinary samples go to the host's tenant with host_id stamped on. Check
// samples (labelled check_id) must name a check in the host's config: its
// own checks go to its tenant as usual; a probe's results for another
// tenant's uptime check go to that tenant, labelled with the probe's region
// instead of a host it doesn't own.
func toPrometheusText(req proto.MetricsRequest, id hostIdentity, hc *hostConfig) (bodies map[string][]byte, kept, dropped int) {
	bufs := map[string]*bytes.Buffer{}
	buf := func(tenantID string) *bytes.Buffer {
		b, ok := bufs[tenantID]
		if !ok {
			b = &bytes.Buffer{}
			bufs[tenantID] = b
		}
		return b
	}
	for _, batch := range req.Batches {
		ts := strconv.FormatInt(batch.TimestampMs, 10)
		for _, s := range batch.Samples {
			if !validSample(s) {
				dropped++
				continue
			}
			tenantID, fixed := id.TenantID, `host_id="`+id.HostID+`"`
			if checkID, ok := s.Labels["check_id"]; ok {
				var c checkDef
				if hc != nil {
					c, ok = hc.checks[checkID]
				}
				if !ok {
					dropped++
					continue
				}
				if c.OnProbes {
					tenantID, fixed = c.TenantID, `probe="`+escapeLabelValue(hc.region)+`"`
				}
			}
			b := buf(tenantID)
			b.WriteString(s.Name)
			b.WriteByte('{')
			b.WriteString(fixed)
			for k, v := range s.Labels {
				if k == "probe" {
					continue
				}
				b.WriteByte(',')
				b.WriteString(k)
				b.WriteString(`="`)
				b.WriteString(escapeLabelValue(v))
				b.WriteByte('"')
			}
			b.WriteString("} ")
			b.WriteString(strconv.FormatFloat(s.Value, 'g', -1, 64))
			b.WriteByte(' ')
			b.WriteString(ts)
			b.WriteByte('\n')
			kept++
		}
	}
	bodies = make(map[string][]byte, len(bufs))
	for t, b := range bufs {
		bodies[t] = b.Bytes()
	}
	return bodies, kept, dropped
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
