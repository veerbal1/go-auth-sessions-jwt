package auth

import (
	"context"
	"errors"
	"testing"
)

func TestLoginSuccess(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	_, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Login Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	user, err := Login(context.Background(), db, LoginInput{
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	if user.ID == "" {
		t.Error("user ID must not be empty")
	}
	if user.Name != "Login Test" {
		t.Errorf("name = %q, want %q", user.Name, "Login Test")
	}
}

func TestLoginWrongPassword(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	user, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Wrong Pass Test",
		Email:    email,
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	_, err = Login(context.Background(), db, LoginInput{
		Email:    email,
		Password: "wrongpassword",
	})
	if err == nil {
		t.Fatal("Login must fail with wrong password")
	}

	var authErr *AuthenticationError
	if !errors.As(err, &authErr) {
		t.Errorf("expected AuthenticationError, got %T: %v", err, err)
	}

	var eventCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_events WHERE event_type = 'auth.login_failed' AND user_id = $1`, user.ID,
	).Scan(&eventCount)
	if eventCount != 1 {
		t.Errorf("auth.login_failed audit event count = %d, want 1", eventCount)
	}
}

func TestLoginUnknownEmail(t *testing.T) {
	db := testDB(t)

	unknownEmail := uniqueEmail()

	_, err := Login(context.Background(), db, LoginInput{
		Email:    unknownEmail,
		Password: "password123",
	})
	if err == nil {
		t.Fatal("Login must fail for unknown email")
	}

	var authErr *AuthenticationError
	if !errors.As(err, &authErr) {
		t.Errorf("expected AuthenticationError, got %T: %v", err, err)
	}

	var eventCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_events
		 WHERE event_type = 'auth.login_failed'
		 AND user_id IS NULL
		 AND metadata->>'email' = $1`,
		unknownEmail,
	).Scan(&eventCount)
	if eventCount != 1 {
		t.Errorf("auth.login_failed audit event count = %d, want 1", eventCount)
	}
}

func TestLoginEmptyEmail(t *testing.T) {
	db := testDB(t)

	_, err := Login(context.Background(), db, LoginInput{
		Email:    "",
		Password: "password123",
	})
	if err == nil {
		t.Fatal("Login must fail for empty email")
	}

	var valErr *ValidationError
	if !errors.As(err, &valErr) {
		t.Errorf("expected ValidationError, got %T: %v", err, err)
	}
}

func TestLoginCaseInsensitiveEmail(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	_, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Case Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	user, err := Login(context.Background(), db, LoginInput{
		Email:    "   " + email + "   ",
		Password: password,
	})
	if err != nil {
		t.Fatalf("Login with whitespace email failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()
}

func TestLoginDisabledUser(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	user, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Disabled Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	_, err = db.ExecContext(context.Background(),
		`UPDATE users SET disabled_at = now() WHERE id = $1`, user.ID,
	)
	if err != nil {
		t.Fatalf("failed to disable user: %v", err)
	}

	_, err = Login(context.Background(), db, LoginInput{
		Email:    email,
		Password: password,
	})
	if err == nil {
		t.Fatal("Login must fail for disabled user")
	}

	var authErr *AuthenticationError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected AuthenticationError, got %T: %v", err, err)
	}
	if authErr.Message != "invalid email or password" {
		t.Errorf("message = %q, want %q", authErr.Message, "invalid email or password")
	}

	var eventCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_events WHERE event_type = 'auth.login_failed' AND user_id = $1`, user.ID,
	).Scan(&eventCount)
	if eventCount != 1 {
		t.Errorf("auth.login_failed audit event count = %d, want 1", eventCount)
	}
}
