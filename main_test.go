package main

import (
	"testing"

	"github.com/Dragonicorn/chirpy/internal/auth"

	"github.com/google/uuid"
)

func (cfg *apiConfig) TestMakeJWT (t *testing.T) {
	// var userID uuid.UUID
	userID, err := uuid.Parse("e385c0bd-af46-48b4-aee5-657ebab5c217")
	str, err := auth.MakeJWT(userID, cfg.secretKey, 60 * 1000)
	if err != nil {
		t.Errorf("Error %v", err)
	}
	t.Errorf("Secret Key %s, Got %v", cfg.secretKey, str)
}

func TestValidateJWT(t *testing.T) {

}