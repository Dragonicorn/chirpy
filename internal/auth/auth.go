package auth

import (
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

/*type chirpyClaims struct {
	Issuer		string
	Subject		string
	ExpiresAt	jwt.NewNumericDate
	IssuedAt	jwt.NewNumericDate
	NotBefore	jwt.NewNumericDate
	jwt.RegisteredClaims
}*/
/*type RegisteredClaims struct {
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

	/*claims := jwt.MapClaims{}
	var userID uuid.UUID
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHS256); !ok {
			return nil, fmt.Errorf("Error with token signing method")
		}
		return secretKey, nil
	})
	if err != nil {
		return nil, err
	//} else if claims, ok := token.Claims.(*claims); ok {
	//	return claims.RegisteredClaims.Subject, nil
	//} else {
	//	return userID, err
	}*/
}

func GetBearerToken(headers http.Header) (string, error) {
	tokenString := strings.TrimPrefix(headers["Authorization"][0], "Bearer ")
	//fmt.Printf("\nAuthorization Token '%v' found\n\n", tokenString)
	if tokenString == "" {
		return tokenString, errors.New("No Bearer Token String provided in request")
	}
	return tokenString, nil
}