package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/veerbal1/go-auth-sessions-jwt/auth"
)

func TestRequireRoleUserAccessAllowed(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	_, err := auth.Signup(context.Background(), db, auth.SignInSignUpParameters{
		Name:     "RoleUser Test",
		Email:    email,
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer db.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, email)

	accessToken := loginAndGetToken(t, db, email, "password123")

	wrapped := RequireAuth(db, testJWTSecret())(RequireRole(db, "user")(MeHandler()))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRequireRoleUserAccessDeniedForAdmin(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	_, err := auth.Signup(context.Background(), db, auth.SignInSignUpParameters{
		Name:     "NoAdmin Test",
		Email:    email,
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer db.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, email)

	accessToken := loginAndGetToken(t, db, email, "password123")

	wrapped := RequireAuth(db, testJWTSecret())(RequireRole(db, "admin")(MeHandler()))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestRequireRoleAdminAccessAllowed(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	user, err := auth.Signup(context.Background(), db, auth.SignInSignUpParameters{
		Name:     "Admin Test",
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

	wrapped := RequireAuth(db, testJWTSecret())(RequireRole(db, "admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"ok": "admin"})
	})))

	req := httptest.NewRequest(http.MethodGet, "/admin/test", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestRequireRoleWithoutAuth(t *testing.T) {
	db := testDB(t)

	wrapped := RequireRole(db, "admin")(MeHandler())

	req := httptest.NewRequest(http.MethodGet, "/admin/test", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestRequireRoleWritesAuditOnDenial(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	_, err := auth.Signup(context.Background(), db, auth.SignInSignUpParameters{
		Name:     "AuditDenial Test",
		Email:    email,
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer db.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, email)

	accessToken := loginAndGetToken(t, db, email, "password123")

	wrapped := RequireAuth(db, testJWTSecret())(RequireRole(db, "admin")(MeHandler()))

	req := httptest.NewRequest(http.MethodGet, "/admin/test", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}

	claims, _ := auth.VerifyAccessToken(testJWTSecret(), accessToken)

	var auditCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_events
		 WHERE event_type = 'auth.access_denied'
		 AND user_id = $1
		 AND metadata->>'reason' = 'insufficient role'`,
		claims.UserID,
	).Scan(&auditCount)
	if auditCount != 1 {
		t.Errorf("audit count = %d, want 1", auditCount)
	}
}
