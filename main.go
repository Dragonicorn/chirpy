package main

import (
	"fmt"
	"net/http"
	"log"
	"sync/atomic"
)

// struct to hold any stateful in-memory data
type apiConfig struct {
	fileserverHits atomic.Int32
}

// increment fileserverHits
func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

// readiness endpoint handler
func readiness_handler (out http.ResponseWriter, req *http.Request) {
	out.Header().Set("Content-Type", "text/plain; charset=utf-8")
	out.WriteHeader(200)
	out.Write([]byte("OK\n"))
}

//number of requests (hits) handler
func (cfg *apiConfig) hits_handler (out http.ResponseWriter, req *http.Request) {
	out.Header().Set("Content-Type", "text/plain; charset=utf-8")
	out.WriteHeader(200)
	out.Write([]byte(fmt.Sprintf("Hits: %v\n", cfg.fileserverHits.Load())))
}

//reset number of requests (hits) handler
func (cfg *apiConfig) resetHits_handler (out http.ResponseWriter, req *http.Request) {
	cfg.fileserverHits.Store(0)
	out.Header().Set("Content-Type", "text/plain; charset=utf-8")
	out.WriteHeader(200)
	out.Write([]byte(fmt.Sprintf("Reset hit count to %v\n", cfg.fileserverHits.Load())))
}

func main() {

	var apiCfg apiConfig
	var ws http.Server
	mux := http.NewServeMux()

	// root directory for file server
	root := "."
	// serve contents of root directory
	fs := http.FileServer(http.Dir(root))
	//register file server handler
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", fs)))

	//register readiness endpoint handler
	mux.HandleFunc("GET /api/healthz", readiness_handler)

	//register reset number of hits handler
	mux.HandleFunc("POST /api/reset", apiCfg.resetHits_handler)
	//register number of hits handler
	mux.HandleFunc("GET /api/metrics", apiCfg.hits_handler)

	// use net/http package to listen and serve on port 8080
	ws.Handler = mux
	ws.Addr = ":8080"
	err := ws.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}