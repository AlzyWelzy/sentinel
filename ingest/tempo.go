package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// hostAttr is set by ingest on every trace from the host token; whatever an
// application put there is replaced.
const hostAttr = "pulsegrid.host_id"

// tempo stores traces, one Tempo tenant (X-Scope-OrgID) per Pulsegrid tenant.
type tempo struct {
	baseURL string
	client  *http.Client
}

// decodeTraces reads an OTLP/HTTP body (protobuf or JSON).
func decodeTraces(contentType string, body []byte) (*collectortrace.ExportTraceServiceRequest, error) {
	req := &collectortrace.ExportTraceServiceRequest{}
	var err error
	if strings.HasPrefix(contentType, "application/json") {
		err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(body, req)
	} else {
		err = proto.Unmarshal(body, req)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid OTLP traces: %w", err)
	}
	return req, nil
}

// stampHost sets pulsegrid.host_id on every resource and counts spans.
func stampHost(req *collectortrace.ExportTraceServiceRequest, hostID string) int {
	spans := 0
	for _, rs := range req.ResourceSpans {
		if rs.Resource == nil {
			rs.Resource = &resourcepb.Resource{}
		}
		attrs := rs.Resource.Attributes[:0]
		for _, a := range rs.Resource.Attributes {
			if a.Key != hostAttr {
				attrs = append(attrs, a)
			}
		}
		rs.Resource.Attributes = append(attrs, &commonpb.KeyValue{
			Key: hostAttr, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: hostID}},
		})
		for _, ss := range rs.ScopeSpans {
			spans += len(ss.Spans)
		}
	}
	return spans
}

func (t *tempo) push(ctx context.Context, tenantID string, req *collectortrace.ExportTraceServiceRequest) error {
	body, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(t.baseURL, "/")+"/v1/traces", bytes.NewReader(body))
	if err != nil {
		return err
	}
	hreq.Header.Set("Content-Type", "application/x-protobuf")
	hreq.Header.Set("X-Scope-OrgID", tenantID)
	resp, err := t.client.Do(hreq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("tempo: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

func (s *server) handleTraces(w http.ResponseWriter, r *http.Request) {
	if s.tempo == nil {
		httpError(w, http.StatusNotFound, "APM isn't enabled")
		return
	}
	id, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	body, err := readBody(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	req, err := decodeTraces(r.Header.Get("Content-Type"), body)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	spans := stampHost(req, id.HostID)
	if spans == 0 {
		writeJSON(w, http.StatusOK, map[string]int{"accepted": 0})
		return
	}
	allowed, err := s.cache.takeQuota(r.Context(), "spanquota", id.HostID, spans, s.cfg.SpansPerMinute)
	if err != nil {
		s.log.Warn("span quota unavailable", "err", err, "host_id", id.HostID)
		allowed = spans
	}
	if allowed < spans {
		// Batches are kept whole (a trace cut in half is worse than none).
		s.log.Warn("trace batch over quota dropped", "host_id", id.HostID, "spans", spans)
		writeJSON(w, http.StatusOK, map[string]int{"accepted": 0, "dropped": spans})
		return
	}
	if err := s.tempo.push(r.Context(), id.TenantID, req); err != nil {
		s.log.Error("trace write failed", "err", err, "host_id", id.HostID)
		httpError(w, http.StatusServiceUnavailable, "trace store unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"accepted": spans})
}
