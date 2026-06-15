package auth

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

func TestRotateRefreshTokenSuccess(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	_, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Rotate Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	result, err := LoginWithRefreshToken(
		context.Background(), db,
		LoginInput{Email: email, Password: password},
		testJWTSecret,
		15*time.Minute, 7*24*time.Hour, 15*time.Minute, "", "",
	)
	if err != nil {
		t.Fatalf("LoginWithRefreshToken failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, email)
	}()

	rotated, err := RotateRefreshToken(
		context.Background(), db,
		result.RefreshToken, testJWTSecret,
		15*time.Minute, 7*24*time.Hour,
	)
	if err != nil {
		t.Fatalf("RotateRefreshToken failed: %v", err)
	}

	if rotated.RefreshToken == "" {
		t.Error("new RefreshToken must not be empty")
	}
	if rotated.RefreshToken == result.RefreshToken {
		t.Error("new RefreshToken must differ from old")
	}
	if rotated.AccessToken == "" {
		t.Error("new AccessToken must not be empty")
	}

	var oldUsedAt sql.NullTime
	var oldReplacedBy string
	db.QueryRowContext(context.Background(),
		`SELECT used_at, replaced_by_token_id FROM refresh_tokens WHERE session_id = $1 AND token_hash = $2`,
		result.SessionID, HashRefreshToken(result.RefreshToken),
	).Scan(&oldUsedAt, &oldReplacedBy)

	if !oldUsedAt.Valid {
		t.Error("old token must be marked as used")
	}
	if oldReplacedBy == "" {
		t.Error("old token must point to replacement")
	}

	var newTokenHash string
	db.QueryRowContext(context.Background(),
		`SELECT token_hash FROM refresh_tokens WHERE id = $1`,
		oldReplacedBy,
	).Scan(&newTokenHash)

	if newTokenHash == rotated.RefreshToken {
		t.Error("DB must not store raw refresh token")
	}
	if newTokenHash != HashRefreshToken(rotated.RefreshToken) {
		t.Error("stored hash must match new raw token")
	}

	claims, err := VerifyAccessToken(testJWTSecret, rotated.AccessToken)
	if err != nil {
		t.Fatalf("new access token must verify: %v", err)
	}
	if claims.SessionID != result.SessionID {
		t.Errorf("access token session = %q, want %q", claims.SessionID, result.SessionID)
	}
}

func TestRotateRefreshTokenOldTokenRejected(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	_, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Replay Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	result, err := LoginWithRefreshToken(
		context.Background(), db,
		LoginInput{Email: email, Password: password},
		testJWTSecret,
		15*time.Minute, 7*24*time.Hour, 15*time.Minute, "", "",
	)
	if err != nil {
		t.Fatalf("LoginWithRefreshToken failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, email)
	}()

	oldRaw := result.RefreshToken

	_, err = RotateRefreshToken(context.Background(), db, oldRaw, testJWTSecret, 15*time.Minute, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("first RotateRefreshToken failed: %v", err)
	}

	_, err = RotateRefreshToken(context.Background(), db, oldRaw, testJWTSecret, 15*time.Minute, 7*24*time.Hour)
	if err == nil {
		t.Fatal("reusing old token must fail")
	}

	var authErr *AuthenticationError
	if !errors.As(err, &authErr) {
		t.Errorf("expected AuthenticationError, got %T", err)
	}
}
