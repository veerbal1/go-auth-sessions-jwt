package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"auth-lab/auth"
)

func TestLogoutHandlerSuccess(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	_, err := auth.Signup(context.Background(), db, auth.SignInSignUpParameters{
		Name:     "Logout Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer db.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, email)

	accessCookie, _ := loginAndGetCookies(t, db, email, password)

	handler := RequireAuth(db, testJWTSecret())(LogoutHandler(db))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/logout", nil)
	req.AddCookie(accessCookie)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	clearedAccess := findCookie(rec.Result().Cookies(), "access_token")
	if clearedAccess == nil || clearedAccess.MaxAge != -1 {
		t.Error("access_token cookie must be cleared")
	}

	clearedRefresh := findCookie(rec.Result().Cookies(), "refresh_token")
	if clearedRefresh == nil || clearedRefresh.MaxAge != -1 {
		t.Error("refresh_token cookie must be cleared")
	}

	var resp logoutResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Message == "" {
		t.Error("response must have a message")
	}

	claims, _ := auth.VerifyAccessToken(testJWTSecret(), accessCookie.Value)
	if claims != nil {
		var auditCount int
		db.QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM audit_events
			 WHERE event_type = 'auth.logout' AND user_id = $1 AND session_id = $2`,
			claims.UserID, claims.SessionID,
		).Scan(&auditCount)
		if auditCount != 1 {
			t.Errorf("auth.logout audit count = %d, want 1", auditCount)
		}
	}
}

func TestLogoutThenMeFails(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	_, err := auth.Signup(context.Background(), db, auth.SignInSignUpParameters{
		Name:     "LogoutMe Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer db.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, email)

	accessCookie, _ := loginAndGetCookies(t, db, email, password)

	logoutHandler := RequireAuth(db, testJWTSecret())(LogoutHandler(db))
	meHandler := RequireAuth(db, testJWTSecret())(MeHandler())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/logout", nil)
	req.AddCookie(accessCookie)
	rec := httptest.NewRecorder()
	logoutHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("logout failed: %d", rec.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req2.AddCookie(accessCookie)
	rec2 := httptest.NewRecorder()
	meHandler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("/me after logout: expected 401, got %d", rec2.Code)
	}
}

func TestLogoutThenRefreshFails(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	_, err := auth.Signup(context.Background(), db, auth.SignInSignUpParameters{
		Name:     "LogoutRefresh Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer db.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, email)

	accessCookie, refreshCookie := loginAndGetCookies(t, db, email, password)

	logoutHandler := RequireAuth(db, testJWTSecret())(LogoutHandler(db))
	refreshHandler := RefreshHandler(db, testJWTSecret())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/logout", nil)
	req.AddCookie(accessCookie)
	rec := httptest.NewRecorder()
	logoutHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("logout failed: %d", rec.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	req2.AddCookie(refreshCookie)
	rec2 := httptest.NewRecorder()
	refreshHandler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("/refresh after logout: expected 401, got %d", rec2.Code)
	}
}

func TestLogoutWithoutAuth(t *testing.T) {
	db := testDB(t)

	handler := RequireAuth(db, testJWTSecret())(LogoutHandler(db))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/logout", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}
