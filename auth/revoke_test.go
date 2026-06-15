package auth

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func TestRevokeSession(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	_, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Revoke Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	result, err := LoginWithRefreshToken(
		context.Background(), db,
		LoginInput{Email: email, Password: password},
		[]byte("test-secret"),
		15*time.Minute, 7*24*time.Hour, 15*time.Minute, "", "",
	)
	if err != nil {
		t.Fatalf("LoginWithRefreshToken failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, email)
	}()

	err = RevokeSession(context.Background(), db, result.SessionID)
	if err != nil {
		t.Fatalf("RevokeSession failed: %v", err)
	}

	var revokedAt sql.NullTime
	var revokeReason sql.NullString
	db.QueryRowContext(context.Background(),
		`SELECT revoked_at, revoke_reason FROM sessions WHERE id = $1`,
		result.SessionID,
	).Scan(&revokedAt, &revokeReason)

	if !revokedAt.Valid {
		t.Error("session revoked_at must be set")
	}
	if revokeReason.String != "logout" {
		t.Errorf("revoke_reason = %q, want %q", revokeReason.String, "logout")
	}

	var refreshRevokedAt sql.NullTime
	var refreshRevokeReason sql.NullString
	db.QueryRowContext(context.Background(),
		`SELECT revoked_at, revoke_reason FROM refresh_tokens WHERE session_id = $1`,
		result.SessionID,
	).Scan(&refreshRevokedAt, &refreshRevokeReason)

	if !refreshRevokedAt.Valid {
		t.Error("refresh token revoked_at must be set")
	}
	if refreshRevokeReason.String != "logout" {
		t.Errorf("refresh revoke_reason = %q, want %q", refreshRevokeReason.String, "logout")
	}

	var auditCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_events
		 WHERE event_type = 'auth.session_revoked' AND session_id = $1`,
		result.SessionID,
	).Scan(&auditCount)
	if auditCount != 1 {
		t.Errorf("auth.session_revoked audit count = %d, want 1", auditCount)
	}
}

func TestRevokeSessionIdempotent(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	_, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Idempotent Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	result, err := LoginWithRefreshToken(
		context.Background(), db,
		LoginInput{Email: email, Password: password},
		[]byte("test-secret"),
		15*time.Minute, 7*24*time.Hour, 15*time.Minute, "", "",
	)
	if err != nil {
		t.Fatalf("LoginWithRefreshToken failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, email)
	}()

	err = RevokeSession(context.Background(), db, result.SessionID)
	if err != nil {
		t.Fatalf("first RevokeSession failed: %v", err)
	}

	err = RevokeSession(context.Background(), db, result.SessionID)
	if err != nil {
		t.Fatalf("second RevokeSession must not error: %v", err)
	}

	var revokedAt sql.NullTime
	var revokeReason sql.NullString
	db.QueryRowContext(context.Background(),
		`SELECT revoked_at, revoke_reason FROM sessions WHERE id = $1`,
		result.SessionID,
	).Scan(&revokedAt, &revokeReason)

	if !revokedAt.Valid {
		t.Error("session must still be revoked after second call")
	}
	if revokeReason.String != "logout" {
		t.Errorf("revoke_reason = %q, want %q", revokeReason.String, "logout")
	}
}
