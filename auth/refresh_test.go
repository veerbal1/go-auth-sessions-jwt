package auth

import (
	"context"
	"testing"
	"time"
)

func TestCreateRefreshToken(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	user, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Refresh Test",
		Email:    email,
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	session, err := CreateSession(context.Background(), db, user.ID, 15*time.Minute, "", "")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	token, err := CreateRefreshToken(context.Background(), db, session.ID, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRefreshToken failed: %v", err)
	}

	if token.RawToken == "" {
		t.Error("RawToken must not be empty")
	}
	if token.ID == "" {
		t.Error("ID must not be empty")
	}
	if token.ExpiresAt.Before(time.Now()) {
		t.Error("ExpiresAt must be in the future")
	}

	var dbTokenHash string
	var dbSessionID string
	var dbExpiresAt time.Time

	err = db.QueryRowContext(context.Background(),
		`SELECT token_hash, session_id, expires_at FROM refresh_tokens WHERE id = $1`,
		token.ID,
	).Scan(&dbTokenHash, &dbSessionID, &dbExpiresAt)
	if err != nil {
		t.Fatalf("failed to read refresh token: %v", err)
	}

	if dbTokenHash == "" {
		t.Error("stored token_hash must not be empty")
	}
	if dbTokenHash == token.RawToken {
		t.Error("stored token_hash must not equal raw token")
	}
	if dbSessionID != session.ID {
		t.Errorf("session_id = %q, want %q", dbSessionID, session.ID)
	}
	if dbExpiresAt.Before(time.Now()) {
		t.Error("db expires_at must be in the future")
	}

	expectedHash := HashRefreshToken(token.RawToken)
	if dbTokenHash != expectedHash {
		t.Error("stored hash must match sha256 of raw token")
	}
}

func TestRefreshTokenHashVerifies(t *testing.T) {
	raw, err := GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken failed: %v", err)
	}

	hash := HashRefreshToken(raw)

	if hash == "" {
		t.Error("hash must not be empty")
	}
	if hash == raw {
		t.Error("hash must not equal raw token")
	}

	hash2 := HashRefreshToken(raw)
	if hash != hash2 {
		t.Error("same raw token must produce same hash")
	}

	hashDifferent := HashRefreshToken(raw + "x")
	if hash == hashDifferent {
		t.Error("different raw token must produce different hash")
	}
}
