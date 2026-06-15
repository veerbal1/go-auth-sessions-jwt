package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

var testJWTSecret = []byte("test-jwt-secret")

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
	}, testJWTSecret, 15*time.Minute, 7*24*time.Hour, 15*time.Minute, "", "")
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

	var emailCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM email_outbox WHERE user_id = $1`, result.UserID,
	).Scan(&emailCount)
	if emailCount != 1 {
		t.Errorf("exactly 1 email outbox row must be created, got %d", emailCount)
	}

	if result.AccessToken == "" {
		t.Error("AccessToken must not be empty")
	}

	claims, err := VerifyAccessToken(testJWTSecret, result.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken failed: %v", err)
	}
	if claims.UserID != result.UserID {
		t.Errorf("claims.UserID = %q, want %q", claims.UserID, result.UserID)
	}
	if claims.SessionID != result.SessionID {
		t.Errorf("claims.SessionID = %q, want %q", claims.SessionID, result.SessionID)
	}

	_, err = VerifyAccessToken([]byte("wrong-secret"), result.AccessToken)
	if err == nil {
		t.Error("wrong secret must fail verification")
	}

	var successCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_events
		 WHERE event_type = 'auth.login_success' AND user_id = $1 AND session_id = $2`,
		result.UserID, result.SessionID,
	).Scan(&successCount)
	if successCount != 1 {
		t.Errorf("auth.login_success audit event count = %d, want 1", successCount)
	}

	var alertCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_events
		 WHERE event_type = 'auth.login_alert_queued' AND user_id = $1 AND session_id = $2`,
		result.UserID, result.SessionID,
	).Scan(&alertCount)
	if alertCount != 1 {
		t.Errorf("auth.login_alert_queued audit event count = %d, want 1", alertCount)
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
	}, testJWTSecret, 15*time.Minute, 7*24*time.Hour, 15*time.Minute, "", "")

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

	var emailCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM email_outbox WHERE user_id = $1`, user.ID,
	).Scan(&emailCount)
	if emailCount != 0 {
		t.Errorf("no email outbox row must be created, got %d", emailCount)
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
	}, testJWTSecret, 15*time.Minute, 7*24*time.Hour, 15*time.Minute, "", "")

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

	var emailCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM email_outbox WHERE user_id = $1`, user.ID,
	).Scan(&emailCount)
	if emailCount != 0 {
		t.Errorf("no email outbox row must be created, got %d", emailCount)
	}
}

func TestLoginWithRefreshTokenRollback(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	user, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Rollback Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	_, err = Login(context.Background(), db, LoginInput{
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("BeginTx failed: %v", err)
	}

	session, err := CreateSession(context.Background(), tx, user.ID, 15*time.Minute, "", "")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	_, err = CreateRefreshToken(context.Background(), tx, session.ID, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRefreshToken failed: %v", err)
	}

	_, err = QueueNewLoginAlert(context.Background(), tx, user.ID, user.Email)
	if err != nil {
		t.Fatalf("QueueNewLoginAlert failed: %v", err)
	}

	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	var rollbackSessionCount, rollbackTokenCount, rollbackEmailCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM sessions WHERE user_id = $1`, user.ID,
	).Scan(&rollbackSessionCount)
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM refresh_tokens rt
		 JOIN sessions s ON s.id = rt.session_id
		 WHERE s.user_id = $1`, user.ID,
	).Scan(&rollbackTokenCount)
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM email_outbox WHERE user_id = $1`, user.ID,
	).Scan(&rollbackEmailCount)

	if rollbackSessionCount != 0 {
		t.Errorf("rollback must remove session, got %d", rollbackSessionCount)
	}
	if rollbackTokenCount != 0 {
		t.Errorf("rollback must remove refresh token, got %d", rollbackTokenCount)
	}
	if rollbackEmailCount != 0 {
		t.Errorf("rollback must remove email outbox, got %d", rollbackEmailCount)
	}
}
