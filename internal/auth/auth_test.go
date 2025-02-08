package auth

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
)

func TestMakeJWT (t *testing.T) {
	userID, err := uuid.Parse("e385c0bd-af46-48b4-aee5-657ebab5c217")
	secretKey := "fivenightsatfreddys"
	str, err := MakeJWT(userID, secretKey, 60 * 1000)
	if err != nil {
		t.Errorf("Error %v", err)
	}
	fmt.Printf("userID: %v / secretKey: %s / tokenString: %s", userID, secretKey, str)
}

func TestValidateJWT(t *testing.T) {

}

func TestGetBearerToken(t *testing.T) {

}