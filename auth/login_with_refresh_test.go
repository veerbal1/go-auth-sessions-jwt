package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLoginWithRefreshTokenSuccess(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	_, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "RefreshLogin Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	result, err := LoginWithRefreshToken(context.Background(), db, LoginInput{
		Email:    email,
		Password: password,
	}, 15*time.Minute, 7*24*time.Hour, "", "")
	if err != nil {
		t.Fatalf("LoginWithRefreshToken failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, result.UserID)
	}()

	if result.UserID == "" {
		t.Error("UserID must not be empty")
	}
	if result.SessionID == "" {
		t.Error("SessionID must not be empty")
	}
	if result.RefreshToken == "" {
		t.Error("RefreshToken must not be empty")
	}
	if result.SessionExpiresAt.Before(time.Now()) {
		t.Error("SessionExpiresAt must be in the future")
	}
	if result.RefreshExpiresAt.Before(time.Now()) {
		t.Error("RefreshExpiresAt must be in the future")
	}

	var dbTokenHash string
	err = db.QueryRowContext(context.Background(),
		`SELECT token_hash FROM refresh_tokens WHERE session_id = $1`,
		result.SessionID,
	).Scan(&dbTokenHash)
	if err != nil {
		t.Fatalf("failed to read refresh token: %v", err)
	}

	if dbTokenHash == result.RefreshToken {
		t.Error("DB must not store raw refresh token")
	}

	expectedHash := HashRefreshToken(result.RefreshToken)
	if dbTokenHash != expectedHash {
		t.Error("DB stored hash must match sha256 of raw token")
	}
}

func TestLoginWithRefreshTokenWrongPassword(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()

	user, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "WrongPass RT Test",
		Email:    email,
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	_, err = LoginWithRefreshToken(context.Background(), db, LoginInput{
		Email:    email,
		Password: "wrongpassword",
	}, 15*time.Minute, 7*24*time.Hour, "", "")

	if err == nil {
		t.Fatal("must fail for wrong password")
	}
	var authErr *AuthenticationError
	if !errors.As(err, &authErr) {
		t.Errorf("expected AuthenticationError, got %T", err)
	}

	var sessionCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM sessions WHERE user_id = $1`, user.ID,
	).Scan(&sessionCount)
	if sessionCount != 0 {
		t.Errorf("no session must be created, got %d", sessionCount)
	}

	var tokenCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM refresh_tokens rt
		 JOIN sessions s ON s.id = rt.session_id
		 WHERE s.user_id = $1`, user.ID,
	).Scan(&tokenCount)
	if tokenCount != 0 {
		t.Errorf("no refresh token must be created, got %d", tokenCount)
	}
}

func TestLoginWithRefreshTokenDisabledUser(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	user, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Disabled RT Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	db.ExecContext(context.Background(),
		`UPDATE users SET disabled_at = now() WHERE id = $1`, user.ID,
	)

	_, err = LoginWithRefreshToken(context.Background(), db, LoginInput{
		Email:    email,
		Password: password,
	}, 15*time.Minute, 7*24*time.Hour, "", "")

	if err == nil {
		t.Fatal("must fail for disabled user")
	}

	var sessionCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM sessions WHERE user_id = $1`, user.ID,
	).Scan(&sessionCount)
	if sessionCount != 0 {
		t.Errorf("no session must be created, got %d", sessionCount)
	}

	var tokenCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM refresh_tokens rt
		 JOIN sessions s ON s.id = rt.session_id
		 WHERE s.user_id = $1`, user.ID,
	).Scan(&tokenCount)
	if tokenCount != 0 {
		t.Errorf("no refresh token must be created, got %d", tokenCount)
	}
}
