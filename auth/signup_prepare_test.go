package auth

import (
	"testing"
)

func TestPrepareSignupValid(t *testing.T) {
	in := SignInSignUpParameters{
		Name:     " Alice ",
		Email:    " Alice@Example.com ",
		Password: "password123",
	}

	out, err := PrepareSignup(in)
	if err != nil {
		t.Fatalf("PrepareSignup failed: %v", err)
	}

	if out.Name != "Alice" {
		t.Errorf("name = %q, want %q", out.Name, "Alice")
	}
	if out.Email != "alice@example.com" {
		t.Errorf("email = %q, want %q", out.Email, "alice@example.com")
	}

	if out.HashedPassword == "" {
		t.Error("HashedPassword must not be empty")
	}
	if out.HashedPassword == in.Password {
		t.Error("HashedPassword must not equal plaintext password")
	}
	if !VerifyPassword(out.HashedPassword, in.Password) {
		t.Error("HashedPassword must verify against original plaintext password")
	}
}

func TestPrepareSignupInvalid(t *testing.T) {
	_, err := PrepareSignup(SignInSignUpParameters{
		Name:     "",
		Email:    "alice@example.com",
		Password: "password123",
	})
	if err == nil {
		t.Error("PrepareSignup must return error for invalid input")
	}
}

func TestPrepareSignupShortPassword(t *testing.T) {
	_, err := PrepareSignup(SignInSignUpParameters{
		Name:     "Alice",
		Email:    "alice@example.com",
		Password: "short",
	})
	if err == nil {
		t.Error("PrepareSignup must return error for short password")
	}
}
