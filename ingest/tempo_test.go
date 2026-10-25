package main

import (
	"testing"

	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

func str(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
}

func TestStampHost(t *testing.T) {
	req := &collectortrace.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{
		{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{str("service.name", "shop"), str(hostAttr, "someone-elses-host")}},
			ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{Name: "GET /"}, {Name: "db"}}}},
		},
		{ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{Name: "job"}}}}}, // no resource
	}}
	body, _ := proto.Marshal(req)
	decoded, err := decodeTraces("application/x-protobuf", body)
	if err != nil {
		t.Fatal(err)
	}
	if n := stampHost(decoded, "host-1"); n != 3 {
		t.Fatalf("spans = %d", n)
	}
	for _, rs := range decoded.ResourceSpans {
		var hosts []string
		for _, a := range rs.Resource.Attributes {
			if a.Key == hostAttr {
				hosts = append(hosts, a.Value.GetStringValue())
			}
		}
		if len(hosts) != 1 || hosts[0] != "host-1" {
			t.Fatalf("host attribute must be ingest's alone: %v", hosts)
		}
	}
	if _, err := decodeTraces("application/json", []byte(`{"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"x"}]}]}]}`)); err != nil {
		t.Fatalf("json: %v", err)
	}
	if _, err := decodeTraces("application/x-protobuf", []byte("not protobuf at all \xff\xff")); err == nil {
		t.Fatal("garbage accepted")
	}
}
