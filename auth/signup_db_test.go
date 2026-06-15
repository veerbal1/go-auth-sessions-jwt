package auth

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set, skipping DB test")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("failed to ping db: %v", err)
	}

	return db
}

func uniqueEmail() string {
	return fmt.Sprintf("test-%d@example.com", time.Now().UnixNano())
}

func TestSignupCreatesUser(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	user, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Test User",
		Email:    email,
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	if user.ID == "" {
		t.Error("user ID must not be empty")
	}
	if user.Name != "Test User" {
		t.Errorf("name = %q, want %q", user.Name, "Test User")
	}
	if user.Email != email {
		t.Errorf("email = %q, want %q", user.Email, email)
	}

	var hashedPassword string
	err = db.QueryRowContext(context.Background(),
		`SELECT hashed_password FROM users WHERE id = $1`, user.ID,
	).Scan(&hashedPassword)
	if err != nil {
		t.Fatalf("failed to read user: %v", err)
	}

	if hashedPassword == "" {
		t.Error("stored password hash must not be empty")
	}
	if hashedPassword == "password123" {
		t.Error("stored password must not be plaintext")
	}
	if !VerifyPassword(hashedPassword, "password123") {
		t.Error("stored password must verify against original password")
	}
}

func TestSignupAssignsDefaultRole(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	user, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Role Test",
		Email:    email,
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	var roleName string
	err = db.QueryRowContext(context.Background(),
		`SELECT r.name FROM roles r
		 JOIN user_roles ur ON r.id = ur.role_id
		 WHERE ur.user_id = $1`, user.ID,
	).Scan(&roleName)
	if err != nil {
		t.Fatalf("failed to check role: %v", err)
	}
	if roleName != "user" {
		t.Errorf("role = %q, want %q", roleName, "user")
	}
}

func TestSignupDuplicateEmailFails(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	user, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "First",
		Email:    email,
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("first Signup failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	_, err = Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Second",
		Email:    email,
		Password: "password456",
	})
	if err == nil {
		t.Error("duplicate email must return error")
	}
}

func TestSignupMixedCaseDuplicateEmailFails(t *testing.T) {
	db := testDB(t)

	mixedEmail := fmt.Sprintf("Mixed-%d@Example.com", time.Now().UnixNano())

	user, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "First",
		Email:    mixedEmail,
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("first Signup failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	lowerEmail := strings.ToLower(mixedEmail)
	_, err = Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Second",
		Email:    lowerEmail,
		Password: "password456",
	})
	if err == nil {
		t.Errorf("mixed-case duplicate must fail: %q and %q", mixedEmail, lowerEmail)
	}
}
