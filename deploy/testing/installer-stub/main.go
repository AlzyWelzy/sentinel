// Command installer-stub stands in for the API and ingest while CI runs the
// real installers on machines we don't have (Windows, FreeBSD, OpenBSD,
// NetBSD). It serves the rendered install scripts and the agent binaries,
// accepts registration and pushes, and counts the pushes so the test can
// check that the installed agent actually reported.
//
//	installer-stub -addr 127.0.0.1:8099 -dist dist -scripts api/app -version 0.9.0
//	GET /pushes    number of metrics pushes received so far
package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/AlzyWelzy/sentinel/proto"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8099", "listen address")
	dist := flag.String("dist", "dist", "directory with sentinel-agent-<os>-<arch> and .sha256 files")
	scripts := flag.String("scripts", "api/app", "directory with install.sh and install.ps1")
	version := flag.String("version", "", "agent version the scripts install")
	flag.Parse()
	base := "http://" + *addr
	var pushes atomic.Int64

	mux := http.NewServeMux()
	for _, name := range []string{"install.sh", "install.ps1"} {
		mux.HandleFunc("GET /"+name, func(w http.ResponseWriter, _ *http.Request) {
			b, err := os.ReadFile(filepath.Join(*scripts, name))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			s := strings.NewReplacer(
				"__DOWNLOAD_URL__", base,
				"__INGEST_URL__", base,
				"__AGENT_VERSION__", *version,
			).Replace(string(b))
			_, _ = w.Write([]byte(s))
		})
	}
	mux.HandleFunc("GET /agent/{version}/{asset}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("version") != *version {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(*dist, filepath.Base(r.PathValue("asset"))))
	})
	config := proto.AgentConfig{IngestURL: base, IntervalSeconds: 10}
	mux.HandleFunc("POST /v1/register", func(w http.ResponseWriter, r *http.Request) {
		var req proto.RegisterRequest
		body := io.Reader(r.Body)
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				http.Error(w, "bad gzip", http.StatusBadRequest)
				return
			}
			body = gz
		}
		if err := json.NewDecoder(body).Decode(&req); err != nil || req.InstallKey == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		log.Printf("register %s (%s %s/%s, agent %s)", req.Hostname, req.Platform, req.OS, req.Arch, req.AgentVersion)
		writeJSON(w, proto.RegisterResponse{HostID: "ci-host", HostToken: "pgh_ci", Config: config})
	})
	mux.HandleFunc("POST /v1/metrics", func(w http.ResponseWriter, _ *http.Request) {
		log.Printf("metrics push %d", pushes.Add(1))
		writeJSON(w, proto.MetricsResponse{Accepted: 1})
	})
	mux.HandleFunc("GET /v1/agent/config", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, config) })
	// Logs and traces: accepted and ignored.
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, proto.LogsResponse{}) })
	mux.HandleFunc("GET /pushes", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, pushes.Load()) })

	log.Printf("listening on %s", base)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
