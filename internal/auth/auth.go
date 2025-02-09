package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

/*
type RegisteredClaims struct {
	Issuer    string                   `json:"iss,omitempty"`
	Subject   string                   `json:"sub,omitempty"`
	Audience  StringOrSlice            `json:"aud,omitempty"`
	ExpiresAt *numericdate.NumericDate `json:"exp,omitempty"`
	NotBefore *numericdate.NumericDate `json:"nbf,omitempty"`
	IssuedAt  *numericdate.NumericDate `json:"iat,omitempty"`
	JWTID     string                   `json:"jti,omitempty"`
}*/

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {

	// Create claims structure with multiple fields populated
	claims := jwt.RegisteredClaims{
		Issuer: "chirpy",
		Subject: userID.String(),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(tokenSecret))
	return tokenString, err
}

func parseToken(tokenString, tokenSecret string) (*jwt.RegisteredClaims, error) {
	// parse the token
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
    	return []byte(tokenSecret), nil
 	})
	if err != nil {
		return nil, fmt.Errorf("Error parsing token: %v", err)
	}
	// type assert the claims
	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("Invalid token claims")
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	var userID uuid.UUID
	claims, err := parseToken(tokenString, tokenSecret)
	if err != nil {
		return userID, err
	}
	userID, err = uuid.Parse(claims.Subject)
	return userID, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	var tokenString string
	var err error
	if _, ok := headers["Authorization"]; ok {
		tokenString = strings.TrimPrefix(headers["Authorization"][0], "Bearer ")
		fmt.Printf("\nAuthorization Token '%v' [length: %d] found\n\n", tokenString, len(tokenString))
	}
	if tokenString == "" {
		err = errors.New("No Bearer Token String provided in request")
	}
	return tokenString, err
}

func MakeRefreshToken() (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		fmt.Printf("MakeRefreshToken: %v reading random number", err)
	}
	return hex.EncodeToString(token), err
}

func GetAPIKey(headers http.Header) (string, error) {
	var apiKey string
	var err error
	if _, ok := headers["Authorization"]; ok {
		apiKey = strings.TrimPrefix(headers["Authorization"][0], "ApiKey ")
		fmt.Printf("\nAuthorization API Key '%v' [length: %d] found\n\n", apiKey, len(apiKey))
	}
	if apiKey == "" {
		err = errors.New("No API Key provided in request")
	}
	return apiKey, err
}

