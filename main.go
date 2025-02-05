package main

import (
	//"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Dragonicorn/chirpy/internal/database"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

// clone of sqlc internal database User structure with JSON tags
type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string	`json:"email"`
}

// struct to hold any stateful in-memory data
type apiConfig struct {
	platform string
	fileserverHits atomic.Int32
	dbQueries *database.Queries
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

//reset handler
func (cfg *apiConfig) reset_handler (w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)
	if cfg.platform != "dev" {
		respondWithError(w, 403, "Unable to perform request")
		return
	}
	err := cfg.dbQueries.DeleteUsers(r.Context())
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("Database error: %s\n", err))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte(fmt.Sprintf("Deleted users and reset hit count to %d\n", cfg.fileserverHits.Load())))
}

// helper functions to ease sending JSON responses
/* payload should be a responseBody struct with arbitrary JSON entries such as:
	var responseBody struct {
		Body string `json:"cleaned_body"`
	}
*/
func respondWithJSON(w http.ResponseWriter, code int, responseBody interface{}) {
	body, err := json.Marshal(responseBody)
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		w.Write(body)
	}
}
func respondWithError(w http.ResponseWriter, code int, msg string) {
	var responseError struct {
		Error string `json:"error"`
	}
	responseError.Error = msg
	respondWithJSON(w, code, responseError)
}

func profanity_filter (text string) string {
	clean_text := ""
	if len(text) > 0 {
		profane_words := []string{"kerfuffle", "sharbert", "fornax"}
		text_words := strings.Split(text, " ")
		for i, word := range text_words {
			for _, test := range profane_words {
				if strings.ToLower(word) == test {
					text_words[i] = "****"
				}
			}
		}
		clean_text = strings.Join(text_words, " ")
	}
	return clean_text
}

//JSON handler
func validateChirp_handler(w http.ResponseWriter, r *http.Request) {
	type reqBody struct {
		Body string `json:"body"`
	}
	type resBody struct {
		Body string `json:"cleaned_body"`
	}
	var requestBody reqBody
	var responseBody resBody

	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		respondWithError(w, 400, "Something went wrong")
		return
	}

	if len(requestBody.Body) > 140 {
		respondWithError(w, 400, "Chirp is too long")
		return
	}
	responseBody.Body = profanity_filter(requestBody.Body)
	respondWithJSON(w, 200, responseBody)
}

func (cfg *apiConfig) createUser_handler(w http.ResponseWriter, r *http.Request) {
	type reqBody struct {
		Email string `json:"email"`
	}
	var requestBody reqBody
	var responseUser database.User
	var responseBody User
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		respondWithError(w, 400, "Something went wrong decoding user request JSON")
		return
	}
	responseUser, err = cfg.dbQueries.CreateUser(r.Context(), requestBody.Email)
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("Database error: %s\n", err))
		return
	}
	responseBody.ID = responseUser.ID
	responseBody.CreatedAt = responseUser.CreatedAt
	responseBody.UpdatedAt = responseUser.UpdatedAt
	responseBody.Email = responseUser.Email
	respondWithJSON(w, 201, responseBody)
}

func main() {
	// load database connection string using environment variable
	godotenv.Load()
	db, err := sql.Open("postgres", os.Getenv("DB_URL"))
	if err != nil {
		log.Fatal(err)
	}

	var apiCfg apiConfig
	apiCfg.platform = os.Getenv("PLATFORM")
	apiCfg.dbQueries = database.New(db)
	var ws http.Server
	mux := http.NewServeMux()

	// root directory for file server
	root := "."
	// serve contents of root directory
	fs := http.FileServer(http.Dir(root))
	//register file server handler
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", fs)))

	//register reset handler
	mux.HandleFunc("POST /admin/reset", apiCfg.reset_handler)
	//register hitcount handler
	mux.HandleFunc("GET /admin/metrics", apiCfg.adminHits_handler)

	//register readiness endpoint handler
	mux.HandleFunc("GET /api/healthz", readiness_handler)
	//register chirp validation handler
	mux.HandleFunc("POST /api/validate_chirp", validateChirp_handler)

	//register create user handler
	mux.HandleFunc("POST /api/users", apiCfg.createUser_handler)

	// use net/http package to listen and serve on port 8080
	ws.Handler = mux
	ws.Addr = ":8080"
	err = ws.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}