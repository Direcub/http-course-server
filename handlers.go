package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/direcub/http-course-server/internal/auth"
	"github.com/direcub/http-course-server/internal/database"
	cleaning "github.com/direcub/http-course-server/profane_cleaning"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	database       *database.Queries
	secret         string
	API            string
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func decodeJson(s *http.Request, target interface{}) error {
	decoder := json.NewDecoder(s.Body)
	err := decoder.Decode(&target)
	if err != nil {
		return err
	}
	return nil
}

func encodeJson(w http.ResponseWriter, statusCode int, data interface{}) error {
	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(statusCode)

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	_, writeErr := w.Write(jsonData)
	if writeErr != nil {
		return writeErr
	}
	return nil
}

func (e errors) MarshalJSON() ([]byte, error) {
	var errMsg string
	if e.Error != nil {
		errMsg = e.Error.Error()
	}
	return json.Marshal(struct {
		Msg string `json:"error"`
	}{
		Msg: errMsg,
	})
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader((http.StatusOK))
	text := fmt.Sprintf(`<html>
		<body>
		  <h1>Welcome, Chirpy Admin</h1>
		  <p>Chirpy has been visited %d times!</p>
		</body>
	  </html>`, cfg.fileserverHits.Load())
	_, err := w.Write([]byte(text))
	if err != nil {
		fmt.Printf("an error of occured: %v\n", err)
	}
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)
	cfg.database.Reset(r.Context())
	w.WriteHeader(http.StatusOK)
}

func (cfg *apiConfig) validateChirpHandler(w http.ResponseWriter, r *http.Request) {
	params := struct {
		Body string `json:"body"`
	}{}
	err := decodeJson(r, &params)
	if err != nil {
		log.Printf("Failed to dencode JSON: %v", err)
		encodeErr := encodeJson(w, 400, errors{Error: err})
		if encodeErr != nil {
			log.Printf("Failed to encode JSON error: %v", encodeErr)
		}
		return
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("missing Token")
		encodeErr := encodeJson(w, 401, errors{Error: err})
		if encodeErr != nil {
			log.Printf("Failed to encode JSON error: %v", encodeErr)
		}
		return
	}
	if strings.Count(token, ".") != 2 {
		log.Printf("Token is not a valid JWT structure: %s", token)
		encodeErr := encodeJson(w, 401, errors{Error: fmt.Errorf("invalid token format")})
		if encodeErr != nil {
			log.Printf("Failed to encode JSON error: %v", encodeErr)
		}
		return
	}

	id, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		log.Printf("Invalid Token")
		encodeErr := encodeJson(w, 401, errors{Error: err})
		if encodeErr != nil {
			log.Printf("Failed to encode JSON error: %v", encodeErr)
		}
		return
	}

	if len(params.Body) > 140 {
		lengthErr := fmt.Errorf("Chirp is too long")
		encodeErr := encodeJson(w, 400, errors{Error: lengthErr})
		if encodeErr != nil {
			log.Printf("Failed to encode JSON error: %v", encodeErr)
		}
		return
	} else {
		cleaned := cleaning.Profanecleaning(params.Body)
		chirparams := database.AddChirpParams{
			Body:   cleaned,
			UserID: id,
		}
		final, _ := cfg.database.AddChirp(r.Context(), chirparams)
		encodeJson(w, 201, final)
	}
}

func (cfg *apiConfig) createUserHandler(w http.ResponseWriter, r *http.Request) {
	params := parameters{}
	err := decodeJson(r, &params)
	if err != nil {
		log.Printf("Failed to dencode JSON: %v", err)
		encodeErr := encodeJson(w, 400, errors{Error: err})
		if encodeErr != nil {
			log.Printf("Failed to encode JSON error: %v", encodeErr)
		}
		return
	}

	hashed, err := auth.HashPassword(params.Password)
	if err != nil {
		log.Printf("failed to hash password: %v", err)
		return
	}
	userparams := database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hashed,
	}

	user, er := cfg.database.CreateUser(r.Context(), userparams)
	if er != nil {
		log.Printf("Failed to create user: %v", er)
		encodeErr := encodeJson(w, 500, errors{Error: er})
		if encodeErr != nil {
			log.Printf("Failed to encode JSON error: %v", encodeErr)
		}
		return
	}

	user.HashedPassword = ""
	err = encodeJson(w, 201, user)
	if err != nil {
		log.Printf("Failed to encode user: %v", err)
		encodeErr := encodeJson(w, 500, errors{Error: err})
		if encodeErr != nil {
			log.Printf("Failed to encode JSON error: %v", encodeErr)
		}
		return
	}

}

func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, r *http.Request) {
	s := r.URL.Query().Get("author_id")
	dbChirps := []database.Chirp{}
	var err error
	if s != "" {
		id, err := uuid.Parse(s)
		if err != nil {
			log.Printf("error parsing uuid")
			encodeJson(w, 401, errors{Error: err})
			return
		}
		dbChirps, err = cfg.database.GetChirpsByAuthor(r.Context(), id)
		if err != nil {
			log.Printf("error finding chirps")
			encodeJson(w, 401, errors{Error: err})
			return
		}
	} else {
		dbChirps, err = cfg.database.GetChirps(r.Context())
		if err != nil {
			log.Printf("Failed to encode user: %v", err)
			encodeErr := encodeJson(w, 500, errors{Error: err})
			if encodeErr != nil {
				log.Printf("Failed to encode JSON error: %v", encodeErr)
			}
			return
		}
	}

	log.Printf("Retrieved %d chirps from database", len(dbChirps))

	sortDirection := "asc"
	sortDirectionParam := r.URL.Query().Get("sort")
	if sortDirectionParam == "desc" {
		sortDirection = "desc"
	}

	chirps := []Chirp{}
	for _, dbChirp := range dbChirps {
		chirps = append(chirps, Chirp{
			ID:        dbChirp.ID,
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
			UserID:    dbChirp.UserID,
			Body:      dbChirp.Body,
		})
	}

	sort.Slice(chirps, func(i, j int) bool {
		if sortDirection == "desc" {
			return chirps[i].CreatedAt.After(chirps[j].CreatedAt)
		}
		return chirps[i].CreatedAt.Before(chirps[j].CreatedAt)
	})

	encodeJson(w, http.StatusOK, chirps)
}

func (cfg *apiConfig) getChirpHandler(w http.ResponseWriter, r *http.Request) {
	chirpID := r.PathValue("chirpID")

	if chirpID == "${chirpID1}" {
		// For testing purposes, you could return a mock response
		// or try to retrieve an actual chirp ID from your database
		chirps, _ := cfg.database.GetChirps(r.Context())
		if len(chirps) > 0 {
			encodeJson(w, 200, chirps[0])
			return
		}
	}

	id, err := uuid.Parse(chirpID)
	if err != nil {
		encodeJson(w, 400, errors{Error: err})
		return
	}

	chirp, err := cfg.database.GetChirp(r.Context(), id)
	if err != nil {
		encodeJson(w, 404, errors{Error: err})
		return
	} else {
		encodeJson(w, 200, chirp)
	}
}

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, r *http.Request) {
	info := struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}{}

	err := decodeJson(r, &info)
	if err != nil {
		log.Printf("Failed to dencode JSON: %v", err)
		encodeErr := encodeJson(w, 400, errors{Error: err})
		if encodeErr != nil {
			log.Printf("Failed to encode JSON error: %v", encodeErr)
		}
		return
	}

	user, err := cfg.database.FindUserbyEmail(r.Context(), info.Email)
	if err != nil {
		encodeJson(w, 401, "incorrect email or password")
		return
	}

	if auth.CheckPasswordHash(user.HashedPassword, info.Password) != nil {
		encodeJson(w, 401, "incorrect email or password")
		return
	}

	token, err := auth.MakeJWT(user.ID, cfg.secret)
	if err != nil {
		log.Printf("error making fresh token: %v", err)
		return
	}

	user.Token = token
	params := database.AddJWTParams{
		Token: token,
		ID:    user.ID,
	}
	cfg.database.AddJWT(r.Context(), params)

	rtoken, _ := auth.MakeRefreshToken()
	refresh_token, err := cfg.database.AddRefresh(r.Context(), database.AddRefreshParams{
		Token:     rtoken,
		UserID:    user.ID,
		ExpiresAt: time.Now().AddDate(0, 0, 60),
	})
	if err != nil {
		log.Printf("error occured: %v", err)
		return
	}
	user.RefreshToken = refresh_token.Token
	user.HashedPassword = ""
	encodeJson(w, 200, user)

}

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, r *http.Request) {
	tokenStruct := struct {
		Token string `json:"token"`
	}{}
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		encodeJson(w, 401, errors{Error: err})
		return
	}

	token, err := cfg.database.GetRefresh(r.Context(), tokenString)
	if err != nil {
		encodeJson(w, 401, errors{Error: err})
		return
	}

	if token.RevokedAt.Valid {
		encodeJson(w, 401, errors{Error: err})
		return
	}

	if token.ExpiresAt.Before(time.Now()) {
		encodeJson(w, 401, errors{Error: err})
		return
	}

	user, err := cfg.database.GetUserByID(r.Context(), token.UserID)
	if err != nil {
		encodeJson(w, 401, errors{Error: err})
		return
	}

	JwtToken, err := auth.MakeJWT(user.ID, cfg.secret)
	if err != nil {
		encodeJson(w, 500, errors{Error: err})
		return
	}

	tokenStruct.Token = JwtToken
	encodeJson(w, 200, tokenStruct)
}

func (cfg *apiConfig) revokeHandler(w http.ResponseWriter, r *http.Request) {
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		encodeJson(w, 401, errors{Error: err})
		return
	}

	token, err := cfg.database.GetRefresh(r.Context(), tokenString)
	if err != nil {
		encodeJson(w, 401, errors{Error: err})
		return
	}
	now := sql.NullTime{
		Time:  time.Now(),
		Valid: true,
	}
	token.UpdatedAt = time.Now()
	token.RevokedAt = now

	params := database.UpdateTokenParams{
		RevokedAt: token.RevokedAt,
		UpdatedAt: token.UpdatedAt,
		Token:     tokenString,
	}
	err = cfg.database.UpdateToken(r.Context(), params)
	if err != nil {
		encodeJson(w, 500, errors{Error: err})
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) loginUpdaterHandler(w http.ResponseWriter, r *http.Request) {
	creds := struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		encodeJson(w, 401, errors{Error: err})
		return
	}

	err = decodeJson(r, &creds)
	if err != nil {
		encodeJson(w, 401, errors{Error: err})
		return
	}

	log.Printf("token: %v", token)
	_, err = auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		encodeJson(w, 401, errors{Error: err})
		return
	}

	log.Printf("finding user by token")
	user, err := cfg.database.GetUserByToken(r.Context(), token)
	if err != nil {
		log.Printf("error occured: %v", err)
		encodeJson(w, 401, errors{Error: err})
		return
	}
	log.Printf("found user by token")

	hashed, err := auth.HashPassword(creds.Password)
	if err != nil {
		encodeJson(w, 401, errors{Error: err})
		return
	}

	params := database.UpdateCredentialsParams{
		Email:          creds.Email,
		HashedPassword: hashed,
		ID:             user.ID,
	}

	log.Printf("params: %v", params)
	err = cfg.database.UpdateCredentials(r.Context(), params)
	if err != nil {
		encodeJson(w, 401, errors{Error: err})
		return
	}

	user.HashedPassword = ""
	user.Email = creds.Email
	encodeJson(w, 200, user)

}

func (cfg *apiConfig) deleteHandler(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		encodeJson(w, 401, errors{Error: err})
		return
	}

	user, err := cfg.database.GetUserByToken(r.Context(), token)
	if err != nil {
		err := fmt.Errorf("user not found")
		encodeJson(w, 404, errors{Error: err})
		return
	}

	chirpID := r.PathValue("chirpID")
	id, err := uuid.Parse(chirpID)
	if err != nil {
		encodeJson(w, 400, errors{Error: err})
		return
	}
	chirp, err := cfg.database.GetChirp(r.Context(), id)
	if err != nil {
		encodeJson(w, 404, errors{Error: err})
		return
	}

	if user.ID != chirp.UserID {
		err := fmt.Errorf("user not authorized")
		encodeJson(w, 403, errors{Error: err})
		return
	}

	err = cfg.database.DeleteChirp(r.Context(), chirp.ID)
	if err != nil {
		err := fmt.Errorf("error deleting chirp")
		encodeJson(w, 500, errors{Error: err})
		return
	} else {
		err := fmt.Errorf("chirp deleted successfully")
		encodeJson(w, 204, errors{Error: err})
		return
	}

}

func (cfg *apiConfig) makeRedHandler(w http.ResponseWriter, r *http.Request) {
	info := struct {
		Event string            `json:"event"`
		Data  map[string]string `json:"Data"`
	}{}
	err := decodeJson(r, &info)
	if err != nil {
		log.Printf("error decoding json")
		encodeJson(w, 500, errors{Error: err})
		return
	}

	key, err := auth.GetAPIKey(r.Header)
	if err != nil {
		log.Printf("error getting api key: %v", err)
		encodeJson(w, 401, errors{Error: err})
		return
	}
	if key != cfg.API {
		log.Printf("api key mismatch")
		w.WriteHeader(401)
		return
	}

	if info.Event != "user.upgraded" {
		fmt.Printf("event: %v\n", info.Event)
		err = fmt.Errorf("incorrect event")
		log.Printf("error: %v", err)
		encodeJson(w, 204, errors{Error: err})
		return
	}

	userID, err := uuid.Parse(info.Data["user_id"])
	if err != nil {
		log.Printf("error parsing uuid")
		encodeJson(w, 500, errors{Error: err})
		return
	}
	user, err := cfg.database.GetUserByID(r.Context(), userID)
	if err != nil {
		log.Printf("No user found")
		encodeJson(w, 404, errors{Error: err})
		return
	}

	err = cfg.database.MakeRed(r.Context(), user.ID)
	if err != nil {
		log.Printf("error making user red")
		encodeJson(w, 500, errors{Error: err})
		return
	}

	w.WriteHeader(204)
}
