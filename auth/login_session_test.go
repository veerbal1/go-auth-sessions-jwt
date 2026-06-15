package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLoginWithSessionSuccess(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	_, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "LoginSession Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	result, err := LoginWithSession(context.Background(), db, LoginInput{
		Email:    email,
		Password: password,
	}, 15*time.Minute, "GoTest/1.0", "hash")
	if err != nil {
		t.Fatalf("LoginWithSession failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, result.UserID)
	}()

	if result.UserID == "" {
		t.Error("UserID must not be empty")
	}
	if result.Name != "LoginSession Test" {
		t.Errorf("Name = %q, want %q", result.Name, "LoginSession Test")
	}
	if result.Email != email {
		t.Errorf("Email = %q, want %q", result.Email, email)
	}
	if result.SessionID == "" {
		t.Error("SessionID must not be empty")
	}
	if result.ExpiresAt.Before(time.Now()) {
		t.Error("ExpiresAt must be in the future")
	}

	var sessionExists bool
	err = db.QueryRowContext(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM sessions WHERE id = $1 AND user_id = $2)`,
		result.SessionID, result.UserID,
	).Scan(&sessionExists)
	if err != nil {
		t.Fatalf("failed to check session: %v", err)
	}
	if !sessionExists {
		t.Error("session row must exist in database")
	}
}

func TestLoginWithSessionWrongPassword(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()

	user, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "WrongPass Test",
		Email:    email,
		Password: "correctpassword",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	_, err = LoginWithSession(context.Background(), db, LoginInput{
		Email:    email,
		Password: "wrong",
	}, 15*time.Minute, "", "")

	if err == nil {
		t.Fatal("LoginWithSession must fail for wrong password")
	}

	var authErr *AuthenticationError
	if !errors.As(err, &authErr) {
		t.Errorf("expected AuthenticationError, got %T", err)
	}

	var sessionCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = $1)`,
		email,
	).Scan(&sessionCount)
	if sessionCount != 0 {
		t.Errorf("no session must be created for wrong password, got %d", sessionCount)
	}
}

func TestLoginWithSessionDisabledUser(t *testing.T) {
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

	db.ExecContext(context.Background(),
		`UPDATE users SET disabled_at = now() WHERE id = $1`, user.ID,
	)

	_, err = LoginWithSession(context.Background(), db, LoginInput{
		Email:    email,
		Password: password,
	}, 15*time.Minute, "", "")

	if err == nil {
		t.Fatal("LoginWithSession must fail for disabled user")
	}

	var sessionCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM sessions WHERE user_id = $1`, user.ID,
	).Scan(&sessionCount)
	if sessionCount != 0 {
		t.Errorf("no session must be created for disabled user, got %d", sessionCount)
	}
}
