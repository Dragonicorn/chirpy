package main

import (
	//"context"
	"database/sql"
	"encoding/json"
	//"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Dragonicorn/chirpy/internal/auth"
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
	hashedPassword string
	Token     string    `json:"token"`
}

// clone of sqlc internal database User structure with JSON tags
type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string	`json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

// struct to hold any stateful in-memory data
type apiConfig struct {
	platform string
	secretKey string
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

func (cfg *apiConfig) postChirp_handler(w http.ResponseWriter, r *http.Request) {
	type reqBody struct {
		Body string `json:"body"`
		UserID uuid.UUID `json:"user_id"`
	}
	type resBody struct {
		Body string `json:"cleaned_body"`
	}
	var requestBody reqBody
	var responseChirp database.Chirp
	var responseBody Chirp
	var userID uuid.UUID
	
	//tokenString := headers["Authorization"][0]
	for h := range r.Header {
		fmt.Printf("\nHeader Attribute: %v, Value: %v", h, h[0])
	}
	fmt.Println()

	userToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 400, "Something went wrong reading Bearer Token String")
		return
	}
	userID, err = auth.ValidateJWT(userToken, cfg.secretKey)
	if err != nil {
		respondWithError(w, 401, "Invalid Bearer Token String")
		return
	}
	err = json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		respondWithError(w, 400, "Something went wrong decoding chirp request JSON")
		return
	}
	if len(requestBody.Body) > 140 {
		respondWithError(w, 400, "Chirp is too long")
		return
	}

	//responseBody.Body = profanity_filter(requestBody.Body)
	//responseChirp, err = cfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{Body: requestBody.Body, UserID: requestBody.UserID})
	responseChirp, err = cfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{Body: requestBody.Body, UserID: userID})
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("Database error: %s\n", err))
		return
	}
	responseBody.ID = responseChirp.ID
	responseBody.CreatedAt = responseChirp.CreatedAt
	responseBody.UpdatedAt = responseChirp.UpdatedAt
	responseBody.Body = responseChirp.Body
	responseBody.UserID = responseChirp.UserID
	respondWithJSON(w, 201, responseBody)
}

func (cfg *apiConfig) getChirp_handler(w http.ResponseWriter, r *http.Request) {
	var response Chirp
	var responseBody []Chirp

	chirpID, err := uuid.Parse(r.PathValue("chirpID"))
	if err == nil {
		responseChirp, err := cfg.dbQueries.GetChirp(r.Context(), chirpID)
		if err != nil {
			respondWithError(w, 404, fmt.Sprintf("Database error: %s\n", err))
			return
		}
		response.ID = responseChirp.ID
		response.CreatedAt = responseChirp.CreatedAt
		response.UpdatedAt = responseChirp.UpdatedAt
		response.Body = responseChirp.Body
		response.UserID = responseChirp.UserID
		responseBody = append(responseBody, response)
		respondWithJSON(w, 200, responseBody[0])
	} else {
		responseChirps, err := cfg.dbQueries.GetChirps(r.Context())
		if err != nil {
			respondWithError(w, 400, fmt.Sprintf("Database error: %s\n", err))
			return
		}
		for _, responseChirp := range responseChirps {
			response.ID = responseChirp.ID
			response.CreatedAt = responseChirp.CreatedAt
			response.UpdatedAt = responseChirp.UpdatedAt
			response.Body = responseChirp.Body
			response.UserID = responseChirp.UserID
			responseBody = append(responseBody, response)
		}
		respondWithJSON(w, 200, responseBody)
	}
}

func (cfg *apiConfig) createUser_handler(w http.ResponseWriter, r *http.Request) {
	type reqBody struct {
		Password string `json:"password"`
		Email string `json:"email"`
	}
	//type createUserParams struct {
	//	Email          string
	//	HashedPassword string
	//}
	var requestBody reqBody
	var responseUser database.User
	var responseBody User
	//var userParams createUserParams
	var hash string
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		respondWithError(w, 400, "Something went wrong decoding user request JSON")
		return
	}
	//userParams.Email = requestBody.Email
	//userParams.HashedPassword, err = HashPassword(requestBody.Password)
	hash, err = auth.HashPassword(requestBody.Password)
	if err != nil {
		respondWithError(w, 400, "Unable to create password hash")
		return
	}
	//responseUser, err = cfg.dbQueries.CreateUser(r.Context(), userParams)
	responseUser, err = cfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{Email: requestBody.Email, HashedPassword: hash})
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

func (cfg *apiConfig) loginUser_handler(w http.ResponseWriter, r *http.Request) {
	type reqBody struct {
		Password string `json:"password"`
		Email string `json:"email"`
		ExpiresIn int `json:"expires_in_seconds"`
	}
	var requestBody reqBody
	var responseUser database.User
	var responseBody User
	var userJWT string
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		respondWithError(w, 400, "Something went wrong decoding user request JSON")
		return
	}
	responseUser, err = cfg.dbQueries.GetUser(r.Context(), requestBody.Email)
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("Database error: %s\n", err))
		return
	}
	err = auth.CheckPasswordHash(requestBody.Password, responseUser.HashedPassword)
	if err != nil {
		respondWithError(w, 401, fmt.Sprintf("Incorrect email or password"))
		return
	}
	// create JWT for session authentication
	if requestBody.ExpiresIn == 0 || requestBody.ExpiresIn > 3600 {
		requestBody.ExpiresIn = 3600
	}
	userJWT, err = auth.MakeJWT(responseUser.ID, cfg.secretKey, time.Duration(requestBody.ExpiresIn) * time.Second)
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("Something went wrong creating security token"))
		return
	}
	responseBody.ID = responseUser.ID
	responseBody.CreatedAt = responseUser.CreatedAt
	responseBody.UpdatedAt = responseUser.UpdatedAt
	responseBody.Email = responseUser.Email
	responseBody.Token = userJWT
	respondWithJSON(w, 200, responseBody)
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
	apiCfg.secretKey = os.Getenv("SECRET_KEY")
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
	mux.HandleFunc("POST /api/chirps", apiCfg.postChirp_handler)
	//register chirp retrieval handler
	mux.HandleFunc("GET /api/chirps", apiCfg.getChirp_handler)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirp_handler)

	//register create user handler
	mux.HandleFunc("POST /api/users", apiCfg.createUser_handler)
	mux.HandleFunc("POST /api/login", apiCfg.loginUser_handler)

	// use net/http package to listen and serve on port 8080
	ws.Handler = mux
	ws.Addr = ":8080"
	err = ws.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}