package main

import (
	"encoding/json"
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

//hitcount handler
func (cfg *apiConfig) adminHits_handler (w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte(fmt.Sprintf("<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>", cfg.fileserverHits.Load())))
}

//reset hitcount handler
func (cfg *apiConfig) resetHits_handler (w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte(fmt.Sprintf("Reset hit count to %d\n", cfg.fileserverHits.Load())))
}

//JSON handler
func validateChirp_handler(w http.ResponseWriter, r *http.Request) {
	type reqBody struct {
		Body string `json:"body"`
	}
	type resError struct {
		Error string `json:"error"`
	}
	type resBody struct {
		Valid bool `json:"valid"`
	}
	var body []byte
	var req_body reqBody
	var res_error resError
	var res_body resBody
	var res_code int

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&req_body)
	if err != nil {
		res_code = 400
		res_error.Error = "Something went wrong"
	}
	if len(req_body.Body) > 140 {
		res_code = 400
		res_error.Error = "Chirp is too long"
	} else {
		res_code = 200
		res_body.Valid = true
	}
	if res_code == 200 {
		body, err = json.Marshal(res_body)
		if err != nil {
			res_code = 400
			res_error.Error = "Something went wrong"
		}
	} 
	if res_code == 400 {
		body, err = json.Marshal(res_error)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(res_code)
	w.Write(body)
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

	//register reset hitcount handler
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHits_handler)
	//register hitcount handler
	mux.HandleFunc("GET /admin/metrics", apiCfg.adminHits_handler)

	//register readiness endpoint handler
	mux.HandleFunc("GET /api/healthz", readiness_handler)
	//register chirp validation handler
	mux.HandleFunc("POST /api/validate_chirp", validateChirp_handler)

	// use net/http package to listen and serve on port 8080
	ws.Handler = mux
	ws.Addr = ":8080"
	err := ws.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}