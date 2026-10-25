package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLogObservations(t *testing.T) {
	var gotAccount, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccount, gotQuery = r.Header.Get("AccountID"), r.URL.Query().Get("query")
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
			{"metric":{"__name__":"hits","host_id":"h1"},"value":[1,"12"]}]}}`))
	}))
	defer srv.Close()
	e := &evaluator{vlogsURL: srv.URL, http: srv.Client()}
	r := rule{Kind: "logs", Target: `level:in(error)`, Threshold: 10, WindowSeconds: 600, LogsAccount: 42}
	obs, err := e.logObservations(context.Background(), r, []host{{ID: "h1"}, {ID: "h2"}})
	if err != nil {
		t.Fatal(err)
	}
	if gotAccount != "42" {
		t.Fatalf("queries must go to the tenant's own account, got %q", gotAccount)
	}
	if !strings.HasPrefix(gotQuery, `_time:600s {host_id=~"h1|h2"} level:in(error) | stats by (host_id)`) {
		t.Fatalf("query %q", gotQuery)
	}
	if !obs["h1"].Breached || obs["h1"].Value != 12 {
		t.Fatalf("12 lines > 10 must breach: %+v", obs["h1"])
	}
	if !obs["h2"].HasData || obs["h2"].Breached {
		t.Fatalf("a quiet host has data and is fine, so it can resolve: %+v", obs["h2"])
	}
	none, _ := (&evaluator{}).logObservations(context.Background(), r, []host{{ID: "h1"}})
	if none != nil {
		t.Fatal("without VictoriaLogs, log rules don't evaluate")
	}
}
