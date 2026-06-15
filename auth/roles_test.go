package auth

import (
	"context"
	"testing"
)

func TestLoadUserRolesAfterSignup(t *testing.T) {
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

	roles, err := LoadUserRoles(context.Background(), db, user.ID)
	if err != nil {
		t.Fatalf("LoadUserRoles failed: %v", err)
	}

	if len(roles) != 1 {
		t.Fatalf("expected 1 role, got %d: %v", len(roles), roles)
	}
	if roles[0] != "user" {
		t.Errorf("role = %q, want %q", roles[0], "user")
	}
}

func TestLoadUserRolesWithAdmin(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	user, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Admin Role Test",
		Email:    email,
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	var adminRoleID string
	db.QueryRowContext(context.Background(),
		`SELECT id FROM roles WHERE name = 'admin'`,
	).Scan(&adminRoleID)

	db.ExecContext(context.Background(),
		`INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`,
		user.ID, adminRoleID,
	)

	roles, err := LoadUserRoles(context.Background(), db, user.ID)
	if err != nil {
		t.Fatalf("LoadUserRoles failed: %v", err)
	}

	if len(roles) != 2 {
		t.Fatalf("expected 2 roles, got %d: %v", len(roles), roles)
	}

	found := make(map[string]bool)
	for _, r := range roles {
		found[r] = true
	}
	if !found["user"] {
		t.Error("must have 'user' role")
	}
	if !found["admin"] {
		t.Error("must have 'admin' role")
	}
}

func TestLoadUserRolesUnknownUser(t *testing.T) {
	db := testDB(t)

	roles, err := LoadUserRoles(context.Background(), db, "00000000-0000-0000-0000-000000000000")
	if err != nil {
		t.Fatalf("LoadUserRoles failed: %v", err)
	}

	if len(roles) != 0 {
		t.Errorf("expected 0 roles for unknown user, got %d", len(roles))
	}
}
