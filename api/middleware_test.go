package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/veerbal1/go-auth-sessions-jwt/auth"
)

func loginAndGetToken(t *testing.T, db *sql.DB, email, password string) string {
	t.Helper()

	result, err := auth.LoginWithRefreshToken(
		context.Background(), db,
		auth.LoginInput{Email: email, Password: password},
		testJWTSecret(),
		15*time.Minute, 7*24*time.Hour, 15*time.Minute, "", "",
	)
	if err != nil {
		t.Fatalf("LoginWithRefreshToken failed: %v", err)
	}
	return result.AccessToken
}

func TestRequireAuthMissingToken(t *testing.T) {
	db := testDB(t)
	handler := RequireAuth(db, testJWTSecret())(MeHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestRequireAuthCookieToken(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	_, err := auth.Signup(context.Background(), db, auth.SignInSignUpParameters{
		Name:     "Cookie Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	accessToken := loginAndGetToken(t, db, email, password)

	handler := RequireAuth(db, testJWTSecret())(MeHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp meResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.UserID == "" {
		t.Error("UserID must not be empty")
	}
	if resp.Name != "Cookie Test" {
		t.Errorf("Name = %q, want %q", resp.Name, "Cookie Test")
	}
	if resp.Email != email {
		t.Errorf("Email = %q, want %q", resp.Email, email)
	}
	if resp.SessionID == "" {
		t.Error("SessionID must not be empty")
	}

	raw := rec.Body.String()
	if strings.Contains(strings.ToLower(raw), "password") {
		t.Error("response must not contain password")
	}
	if strings.Contains(raw, "access_token") {
		t.Error("response must not contain access_token")
	}

	found := make(map[string]bool)
	for _, r := range resp.Roles {
		found[r] = true
	}
	if !found["user"] {
		t.Error("roles must contain 'user'")
	}

	db.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, email)
}

func TestRequireAuthBearerToken(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	_, err := auth.Signup(context.Background(), db, auth.SignInSignUpParameters{
		Name:     "Bearer Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	accessToken := loginAndGetToken(t, db, email, password)

	handler := RequireAuth(db, testJWTSecret())(MeHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp meResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Name != "Bearer Test" {
		t.Errorf("Name = %q, want %q", resp.Name, "Bearer Test")
	}

	db.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, email)
}

func TestRequireAuthRevokedSession(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	_, err := auth.Signup(context.Background(), db, auth.SignInSignUpParameters{
		Name:     "Revoked Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	result, err := auth.LoginWithRefreshToken(
		context.Background(), db,
		auth.LoginInput{Email: email, Password: password},
		testJWTSecret(),
		15*time.Minute, 7*24*time.Hour, 15*time.Minute, "", "",
	)
	if err != nil {
		t.Fatalf("LoginWithRefreshToken failed: %v", err)
	}
	defer db.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, email)

	db.ExecContext(context.Background(),
		`UPDATE sessions SET revoked_at = now() WHERE id = $1`, result.SessionID,
	)

	handler := RequireAuth(db, testJWTSecret())(MeHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: result.AccessToken})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for revoked session, got %d", rec.Code)
	}

	var auditCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_events
		 WHERE event_type = 'auth.access_denied' AND session_id = $1
		 AND metadata->>'reason' = 'session revoked'`,
		result.SessionID,
	).Scan(&auditCount)
	if auditCount != 1 {
		t.Errorf("auth.access_denied audit count = %d, want 1", auditCount)
	}
}

func TestRequireAuthExpiredSession(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	_, err := auth.Signup(context.Background(), db, auth.SignInSignUpParameters{
		Name:     "Expired Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	result, err := auth.LoginWithRefreshToken(
		context.Background(), db,
		auth.LoginInput{Email: email, Password: password},
		testJWTSecret(),
		15*time.Minute, 7*24*time.Hour, 15*time.Minute, "", "",
	)
	if err != nil {
		t.Fatalf("LoginWithRefreshToken failed: %v", err)
	}
	defer db.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, email)

	db.ExecContext(context.Background(),
		`UPDATE sessions SET expires_at = now() - interval '1 hour' WHERE id = $1`, result.SessionID,
	)

	handler := RequireAuth(db, testJWTSecret())(MeHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: result.AccessToken})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired session, got %d", rec.Code)
	}

	var auditCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_events
		 WHERE event_type = 'auth.access_denied' AND session_id = $1
		 AND metadata->>'reason' = 'session expired'`,
		result.SessionID,
	).Scan(&auditCount)
	if auditCount != 1 {
		t.Errorf("auth.access_denied audit count = %d, want 1", auditCount)
	}
}

func TestRequireAuthDisabledUser(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	user, err := auth.Signup(context.Background(), db, auth.SignInSignUpParameters{
		Name:     "Disabled Auth Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	result, err := auth.LoginWithRefreshToken(
		context.Background(), db,
		auth.LoginInput{Email: email, Password: password},
		testJWTSecret(),
		15*time.Minute, 7*24*time.Hour, 15*time.Minute, "", "",
	)
	if err != nil {
		t.Fatalf("LoginWithRefreshToken failed: %v", err)
	}
	defer db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)

	db.ExecContext(context.Background(),
		`UPDATE users SET disabled_at = now() WHERE id = $1`, user.ID,
	)

	handler := RequireAuth(db, testJWTSecret())(MeHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: result.AccessToken})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for disabled user, got %d", rec.Code)
	}

	var auditCount int
	db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_events
		 WHERE event_type = 'auth.access_denied' AND user_id = $1
		 AND metadata->>'reason' = 'user disabled'`,
		user.ID,
	).Scan(&auditCount)
	if auditCount != 1 {
		t.Errorf("auth.access_denied audit count = %d, want 1", auditCount)
	}
}

func TestRequireAuthInvalidJWT(t *testing.T) {
	db := testDB(t)

	handler := RequireAuth(db, testJWTSecret())(MeHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "invalid.jwt.token"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestRequireAuthBearerTokenWithoutCookie(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	_, err := auth.Signup(context.Background(), db, auth.SignInSignUpParameters{
		Name:     "Priority Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	accessToken := loginAndGetToken(t, db, email, password)

	handler := RequireAuth(db, testJWTSecret())(MeHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with Bearer token, got %d", rec.Code)
	}

	db.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, email)
}
