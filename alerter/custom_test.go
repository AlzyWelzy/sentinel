package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCustomDetailNamesTheSeries(t *testing.T) {
	var gotQuery, gotTenant string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery, gotTenant = r.URL.Query().Get("query"), r.URL.Query().Get("extra_label")
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
			{"metric":{"__name__":"sentinel_custom_lvm_metadata_percent","host_id":"h1","pool":"san/thin"},"value":[1,"85"]},
			{"metric":{"__name__":"sentinel_custom_lvm_metadata_percent","host_id":"h1","pool":"pve/data"},"value":[1,"91.25"]},
			{"metric":{"__name__":"sentinel_custom_lvm_metadata_percent","host_id":"h1","pool":"ok/pool"},"value":[1,"12"]},
			{"metric":{"__name__":"sentinel_custom_lvm_metadata_percent","host_id":"h1","pool":"nan"},"value":[1,"NaN"]}]}}`))
	}))
	defer srv.Close()
	e := &evaluator{vmURL: srv.URL, http: srv.Client()}
	r := rule{TenantID: "t1", Kind: "custom", Target: "lvm_metadata_percent", Operator: ">", Threshold: 80, Aggregation: "avg", WindowSeconds: 600,
		Labels: map[string]string{"pool": "pve/data"}}
	got := e.customDetail(context.Background(), r, host{ID: "h1"})
	if got != "pool=pve/data 91.25; pool=san/thin 85" {
		t.Fatalf("detail %q", got)
	}
	if gotTenant != "tenant_id=t1" {
		t.Fatalf("query must be scoped to the tenant: %q", gotTenant)
	}
	if !strings.HasPrefix(gotQuery, `last_over_time(sentinel_custom_lvm_metadata_percent{host_id="h1",pool="pve/data"}[5m])`) {
		t.Fatalf("query %q", gotQuery)
	}
}
