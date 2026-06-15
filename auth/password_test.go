package auth

import (
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	plaintext := "password123"

	hash, err := HashPassword(plaintext)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if hash == "" {
		t.Error("hash must not be empty")
	}

	if hash == plaintext {
		t.Error("hash must not equal plaintext password")
	}

	if !VerifyPassword(hash, plaintext) {
		t.Error("VerifyPassword must return true for correct password")
	}
}

func TestVerifyPasswordWrongPassword(t *testing.T) {
	hash, err := HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if VerifyPassword(hash, "wrong-password") {
		t.Error("VerifyPassword must return false for wrong password")
	}
}

func TestHashPasswordEmptyPassword(t *testing.T) {
	hash, err := HashPassword("")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if !VerifyPassword(hash, "") {
		t.Error("empty password must verify against its own hash")
	}
}
