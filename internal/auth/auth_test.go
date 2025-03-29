package auth

import (
	"testing"

	"github.com/google/uuid"
)

//func TestJWT(t *testing.T) {
//	tests := []struct {
//		tokenString string
//		tokenSecret string
//	}{
//		{
//			tokenString: "valid.jwt.token",
//			tokenSecret: "secret",
//		},
//	}
//	for _, c := range tests{
//		newID := uuid.New()
//	testString, err := MakeJWT(newID, c.tokenSecret, time.Hour)
//	if err != nil {
//		t.Errorf("failure at making JWT: %v", err)
//	}
//	passedID, err := ValidateJWT(testString, c.tokenSecret)
//	if err != nil {
//		t.Errorf("failure at validating JWT: %v", err)
//	}
//	if newID != passedID {
//		t.Errorf("id missmatch")
//	}
//	}
//
//}

func TestJWT(t *testing.T) {
	// Test case for valid token
	t.Run("Valid token", func(t *testing.T) {
		userID := uuid.New()
		secret := "test-secret"

		// Create a token
		tokenString, err := MakeJWT(userID, secret)
		if err != nil {
			t.Fatalf("Failed to create JWT: %v", err)
		}

		// Validate the token
		parsedID, err := ValidateJWT(tokenString, secret)
		if err != nil {
			t.Errorf("Failed to validate valid JWT: %v", err)
		}

		if parsedID != userID {
			t.Errorf("ID mismatch: got %v, want %v", parsedID, userID)
		}
	})

	// Test case for expired token
	t.Run("Expired token", func(t *testing.T) {
		userID := uuid.New()
		secret := "test-secret"

		// Create a token that expires immediately
		tokenString, err := MakeJWT(userID, secret)
		if err != nil {
			t.Fatalf("Failed to create JWT: %v", err)
		}

		// Validate the token - should fail
		_, err = ValidateJWT(tokenString, secret)
		if err == nil {
			t.Error("Expected error for expired token, got nil")
		}
	})

	t.Run("Wrong secret", func(t *testing.T) {
		userID := uuid.New()
		secret := "test-secret"

		tokenstring, err := MakeJWT(userID, secret)
		if err != nil {
			t.Fatalf("Failed to create JWT: %v", err)
		}

		_, err = ValidateJWT(tokenstring, "secret-test")
		if err == nil {
			t.Fatalf("Mismatched secrets produced same keys")
		}
	})
}
