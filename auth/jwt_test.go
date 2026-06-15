package auth

import (
	"testing"
	"time"
)

func TestGenerateAndVerifyAccessToken(t *testing.T) {
	secret := []byte("test-secret")
	userID := "user-123"
	sessionID := "session-456"

	token, err := GenerateAccessToken(secret, userID, sessionID, 15*time.Minute)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}
	if token == "" {
		t.Fatal("token must not be empty")
	}

	claims, err := VerifyAccessToken(secret, token)
	if err != nil {
		t.Fatalf("VerifyAccessToken failed: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("UserID = %q, want %q", claims.UserID, userID)
	}
	if claims.SessionID != sessionID {
		t.Errorf("SessionID = %q, want %q", claims.SessionID, sessionID)
	}
	if claims.ExpiresAt == nil {
		t.Fatal("ExpiresAt must not be nil")
	}
	if claims.ExpiresAt.Time.Before(time.Now()) {
		t.Error("token must not be expired")
	}
}

func TestVerifyAccessTokenWrongSecret(t *testing.T) {
	secret := []byte("correct-secret")
	wrongSecret := []byte("wrong-secret")

	token, err := GenerateAccessToken(secret, "user-1", "session-1", 15*time.Minute)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	_, err = VerifyAccessToken(wrongSecret, token)
	if err == nil {
		t.Fatal("must fail with wrong secret")
	}
}

func TestVerifyAccessTokenExpired(t *testing.T) {
	secret := []byte("test-secret")

	token, err := GenerateAccessToken(secret, "user-1", "session-1", -1*time.Minute)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	_, err = VerifyAccessToken(secret, token)
	if err == nil {
		t.Fatal("must fail for expired token")
	}
}

func TestVerifyAccessTokenInvalidString(t *testing.T) {
	secret := []byte("secret")

	_, err := VerifyAccessToken(secret, "not-a-valid-jwt")
	if err == nil {
		t.Fatal("must fail for invalid token string")
	}
}
