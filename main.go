package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/direcub/http-course-server/healthz"
	"github.com/direcub/http-course-server/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type parameters struct {
	Body     string `json:"body"`
	Email    string `json:"email"`
	User_id  string `json:"user_id"`
	Password string `json:"password"`
}

type errors struct {
	Error error `json:"error"`
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	secret := os.Getenv("Secret")
	api_key := os.Getenv("POLKA_KEY")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("problem establishing database connection")
	}
	dbQueries := database.New(db)
	apiCfg := &apiConfig{secret: secret, database: dbQueries, API: api_key}

	mux := http.NewServeMux()
	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	fileServer := http.FileServer(http.Dir("."))
	wrapped := apiCfg.middlewareMetricsInc(http.StripPrefix("/app", fileServer))
	mux.Handle("/app/", wrapped)
	mux.HandleFunc("GET /api/healthz", healthz.Handler)
	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)
	mux.HandleFunc("POST /api/chirps", apiCfg.validateChirpHandler)
	mux.HandleFunc("POST /api/users", apiCfg.createUserHandler)
	mux.HandleFunc("GET /api/chirps", apiCfg.getChirpsHandler)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpHandler)
	mux.HandleFunc("POST /api/login", apiCfg.loginHandler)
	mux.HandleFunc("POST /api/refresh", apiCfg.refreshHandler)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeHandler)
	mux.HandleFunc("PUT /api/users", apiCfg.loginUpdaterHandler)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteHandler)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.makeRedHandler)

	err = server.ListenAndServe()
	if err != nil {
		fmt.Println(err)
	}

}
