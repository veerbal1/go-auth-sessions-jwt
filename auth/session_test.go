package auth

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func TestCreateSession(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	user, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Session Test",
		Email:    email,
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	session, err := CreateSession(context.Background(), db, user.ID, 15*time.Minute, "GoTest/1.0", "hash-of-127.0.0.1")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	if session.ID == "" {
		t.Error("session ID must not be empty")
	}

	if session.ExpiresAt.Before(time.Now()) {
		t.Error("expires_at must be in the future")
	}

	var dbUserID string
	var dbExpiresAt time.Time
	var dbRevokedAt sql.NullTime
	var dbUserAgent string
	var dbIPHash string

	err = db.QueryRowContext(context.Background(),
		`SELECT user_id, expires_at, revoked_at, user_agent, ip_hash FROM sessions WHERE id = $1`,
		session.ID,
	).Scan(&dbUserID, &dbExpiresAt, &dbRevokedAt, &dbUserAgent, &dbIPHash)
	if err != nil {
		t.Fatalf("failed to read session: %v", err)
	}

	if dbUserID != user.ID {
		t.Errorf("user_id = %q, want %q", dbUserID, user.ID)
	}

	if dbExpiresAt.Before(time.Now()) {
		t.Error("db expires_at must be in the future")
	}

	if dbRevokedAt.Valid {
		t.Error("revoked_at must be null on creation")
	}

	if dbUserAgent != "GoTest/1.0" {
		t.Errorf("user_agent = %q, want %q", dbUserAgent, "GoTest/1.0")
	}

	if dbIPHash != "hash-of-127.0.0.1" {
		t.Errorf("ip_hash = %q, want %q", dbIPHash, "hash-of-127.0.0.1")
	}
}
