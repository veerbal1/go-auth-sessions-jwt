package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auth-lab/auth"
)

func TestAdminUsersSuccess(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	user, err := auth.Signup(context.Background(), db, auth.SignInSignUpParameters{
		Name:     "AdminUser Test",
		Email:    email,
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer db.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, email)

	var adminRoleID string
	db.QueryRowContext(context.Background(),
		`SELECT id FROM roles WHERE name = 'admin'`,
	).Scan(&adminRoleID)
	db.ExecContext(context.Background(),
		`INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`,
		user.ID, adminRoleID,
	)

	accessToken := loginAndGetToken(t, db, email, "password123")

	wrapped := RequireAuth(db, testJWTSecret())(RequireRole(db, "admin")(AdminUsersHandler(db)))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	raw := rec.Body.String()

	var users []adminUserResponse
	if err := json.Unmarshal([]byte(raw), &users); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if len(users) == 0 {
		t.Fatal("expected at least 1 user")
	}

	for _, u := range users {
		if u.ID == "" {
			t.Error("each user must have ID")
		}
		if u.Name == "" {
			t.Error("each user must have Name")
		}
		if u.Email == "" {
			t.Error("each user must have Email")
		}
	}

	if strings.Contains(raw, "hashed_password") {
		t.Error("response must not contain hashed_password")
	}
	if strings.Contains(raw, "token_hash") {
		t.Error("response must not contain token_hash")
	}
}

func TestAdminUsersNormalUserForbidden(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	_, err := auth.Signup(context.Background(), db, auth.SignInSignUpParameters{
		Name:     "NormalUser Test",
		Email:    email,
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer db.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, email)

	accessToken := loginAndGetToken(t, db, email, "password123")

	wrapped := RequireAuth(db, testJWTSecret())(RequireRole(db, "admin")(AdminUsersHandler(db)))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestAdminUsersUnauthenticated(t *testing.T) {
	db := testDB(t)

	wrapped := RequireAuth(db, testJWTSecret())(RequireRole(db, "admin")(AdminUsersHandler(db)))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}
