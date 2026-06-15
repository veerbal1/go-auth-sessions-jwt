package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestValidateRefreshTokenSuccess(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	user, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Validate RT",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	result, err := LoginWithRefreshToken(
		context.Background(), db,
		LoginInput{Email: email, Password: password},
		[]byte("test-secret"),
		15*time.Minute, 7*24*time.Hour, 15*time.Minute, "", "",
	)
	if err != nil {
		t.Fatalf("LoginWithRefreshToken failed: %v", err)
	}

	validated, err := ValidateRefreshToken(context.Background(), db, result.RefreshToken)
	if err != nil {
		t.Fatalf("ValidateRefreshToken failed: %v", err)
	}

	if validated.TokenID == "" {
		t.Error("TokenID must not be empty")
	}
	if validated.SessionID != result.SessionID {
		t.Errorf("SessionID = %q, want %q", validated.SessionID, result.SessionID)
	}
	if validated.UserID != result.UserID {
		t.Errorf("UserID = %q, want %q", validated.UserID, result.UserID)
	}
	if validated.Name != user.Name {
		t.Errorf("Name = %q, want %q", validated.Name, user.Name)
	}
	if validated.Email != email {
		t.Errorf("Email = %q, want %q", validated.Email, email)
	}
}

func TestValidateRefreshTokenUnknown(t *testing.T) {
	db := testDB(t)

	_, err := ValidateRefreshToken(context.Background(), db, "unknown-refresh-token-value")
	if err == nil {
		t.Fatal("must fail for unknown token")
	}
	var authErr *AuthenticationError
	if !errors.As(err, &authErr) {
		t.Errorf("expected AuthenticationError, got %T", err)
	}
}

func TestValidateRefreshTokenExpired(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	user, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Expired RT",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	result, err := LoginWithRefreshToken(
		context.Background(), db,
		LoginInput{Email: email, Password: password},
		[]byte("test-secret"),
		15*time.Minute, 7*24*time.Hour, 15*time.Minute, "", "",
	)
	if err != nil {
		t.Fatalf("LoginWithRefreshToken failed: %v", err)
	}

	var tokenID string
	db.QueryRowContext(context.Background(),
		`SELECT id FROM refresh_tokens WHERE session_id = $1`, result.SessionID,
	).Scan(&tokenID)
	db.ExecContext(context.Background(),
		`UPDATE refresh_tokens SET expires_at = now() - interval '1 hour' WHERE id = $1`,
		tokenID,
	)

	_, err = ValidateRefreshToken(context.Background(), db, result.RefreshToken)
	if err == nil {
		t.Fatal("must fail for expired token")
	}
	var authErr *AuthenticationError
	if !errors.As(err, &authErr) {
		t.Errorf("expected AuthenticationError, got %T", err)
	}
}

func TestValidateRefreshTokenAcceptsUsedToken(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	user, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Used RT",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	result, err := LoginWithRefreshToken(
		context.Background(), db,
		LoginInput{Email: email, Password: password},
		[]byte("test-secret"),
		15*time.Minute, 7*24*time.Hour, 15*time.Minute, "", "",
	)
	if err != nil {
		t.Fatalf("LoginWithRefreshToken failed: %v", err)
	}

	db.ExecContext(context.Background(),
		`UPDATE refresh_tokens SET used_at = now() WHERE session_id = $1`, result.SessionID,
	)

	_, err = ValidateRefreshToken(context.Background(), db, result.RefreshToken)
	if err != nil {
		t.Fatalf("ValidateRefreshToken must accept used token for reuse detection: %v", err)
	}
}

func TestValidateRefreshTokenRevokedToken(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	user, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Revoked RT Token",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	result, err := LoginWithRefreshToken(
		context.Background(), db,
		LoginInput{Email: email, Password: password},
		[]byte("test-secret"),
		15*time.Minute, 7*24*time.Hour, 15*time.Minute, "", "",
	)
	if err != nil {
		t.Fatalf("LoginWithRefreshToken failed: %v", err)
	}

	db.ExecContext(context.Background(),
		`UPDATE refresh_tokens SET revoked_at = now() WHERE session_id = $1`, result.SessionID,
	)

	_, err = ValidateRefreshToken(context.Background(), db, result.RefreshToken)
	if err == nil {
		t.Fatal("must fail for revoked token")
	}
	var authErr *AuthenticationError
	if !errors.As(err, &authErr) {
		t.Errorf("expected AuthenticationError, got %T", err)
	}
}

func TestValidateRefreshTokenRevokedSession(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	user, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Revoked Session RT",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	result, err := LoginWithRefreshToken(
		context.Background(), db,
		LoginInput{Email: email, Password: password},
		[]byte("test-secret"),
		15*time.Minute, 7*24*time.Hour, 15*time.Minute, "", "",
	)
	if err != nil {
		t.Fatalf("LoginWithRefreshToken failed: %v", err)
	}

	db.ExecContext(context.Background(),
		`UPDATE sessions SET revoked_at = now() WHERE id = $1`, result.SessionID,
	)

	_, err = ValidateRefreshToken(context.Background(), db, result.RefreshToken)
	if err == nil {
		t.Fatal("must fail for revoked session")
	}
	var authErr *AuthenticationError
	if !errors.As(err, &authErr) {
		t.Errorf("expected AuthenticationError, got %T", err)
	}
}

func TestValidateRefreshTokenDisabledUser(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	user, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Disabled RT User",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	result, err := LoginWithRefreshToken(
		context.Background(), db,
		LoginInput{Email: email, Password: password},
		[]byte("test-secret"),
		15*time.Minute, 7*24*time.Hour, 15*time.Minute, "", "",
	)
	if err != nil {
		t.Fatalf("LoginWithRefreshToken failed: %v", err)
	}

	db.ExecContext(context.Background(),
		`UPDATE users SET disabled_at = now() WHERE id = $1`, user.ID,
	)

	_, err = ValidateRefreshToken(context.Background(), db, result.RefreshToken)
	if err == nil {
		t.Fatal("must fail for disabled user")
	}
	var authErr *AuthenticationError
	if !errors.As(err, &authErr) {
		t.Errorf("expected AuthenticationError, got %T", err)
	}
}
