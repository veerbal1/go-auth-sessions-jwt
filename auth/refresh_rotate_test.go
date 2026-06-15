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

	var rotatedCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_events
		 WHERE event_type = 'auth.refresh_rotated' AND session_id = $1`,
		result.SessionID,
	).Scan(&rotatedCount)
	if rotatedCount != 1 {
		t.Errorf("auth.refresh_rotated audit count = %d, want 1", rotatedCount)
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

	var reuseCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_events
		 WHERE event_type = 'auth.refresh_reuse_detected' AND session_id = $1`,
		result.SessionID,
	).Scan(&reuseCount)
	if reuseCount != 1 {
		t.Errorf("auth.refresh_reuse_detected audit count = %d, want 1", reuseCount)
	}

	var sessionRevoked sql.NullTime
	var sessionReason sql.NullString
	db.QueryRowContext(context.Background(),
		`SELECT revoked_at, revoke_reason FROM sessions WHERE id = $1`,
		result.SessionID,
	).Scan(&sessionRevoked, &sessionReason)
	if !sessionRevoked.Valid {
		t.Error("session must be revoked on reuse")
	}
	if sessionReason.String != "refresh_reuse" {
		t.Errorf("session revoke_reason = %q, want %q", sessionReason.String, "refresh_reuse")
	}

	var tokenRevoked sql.NullTime
	var tokenReason sql.NullString
	db.QueryRowContext(context.Background(),
		`SELECT revoked_at, revoke_reason FROM refresh_tokens WHERE session_id = $1`,
		result.SessionID,
	).Scan(&tokenRevoked, &tokenReason)
	if !tokenRevoked.Valid {
		t.Error("refresh tokens must be revoked on reuse")
	}
	if tokenReason.String != "refresh_reuse" {
		t.Errorf("token revoke_reason = %q, want %q", tokenReason.String, "refresh_reuse")
	}
}
