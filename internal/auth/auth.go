package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), 0)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

func CheckPasswordHash(hash, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return err
	}
	return nil
}

func MakeJWT(userID uuid.UUID, tokenSecret string) (string, error) {
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		Subject:   uuid.UUID.String(userID),
	})
	signed, err := newToken.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}
	return signed, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) { return []byte(tokenSecret), nil })
	if err != nil {
		return uuid.Nil, err
	}

	if !token.Valid {
		return uuid.Nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return uuid.Nil, fmt.Errorf("could not parse claims as RegisteredClaims")
	}

	subject, err := claims.GetSubject()
	if err != nil {
		return uuid.Nil, err
	}

	userID, err := uuid.Parse(subject)
	if err != nil {
		return uuid.Nil, err
	}
	return userID, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	strng := headers.Get("Authorization")
	if len(strng) == 0 {
		return "", fmt.Errorf("no auth header found")
	}
	split := strings.Split(strng, " ")
	if len(split) != 2 || split[0] != "Bearer" {
		return "", fmt.Errorf("malformed auth header")
	}

	return split[1], nil
}

func GetAPIKey(headers http.Header) (string, error) {
	strng := headers.Get("Authorization")
	if len(strng) == 0 {
		return "", fmt.Errorf("no auth header found")
	}
	split := strings.Split(strng, " ")
	if len(split) != 2 || split[0] != "ApiKey" {
		log.Printf("header slot one: %v", split[0])
		return "", fmt.Errorf("malformed auth header")
	}

	return split[1], nil
}

func MakeRefreshToken() (string, error) {
	holder := make([]byte, 32)
	if _, err := rand.Read(holder); err != nil {
		return "", err
	}
	string := hex.EncodeToString(holder)
	return string, nil
}
