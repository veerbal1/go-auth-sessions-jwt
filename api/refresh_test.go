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

	"auth-lab/auth"
)

func loginAndGetCookies(t *testing.T, db *sql.DB, email, password string) (*http.Cookie, *http.Cookie) {
	t.Helper()

	result, err := auth.LoginWithRefreshToken(
		context.Background(), db,
		auth.LoginInput{Email: email, Password: password},
		testJWTSecret(),
		15*time.Minute, 7*24*time.Hour, 15*time.Minute, "", "",
	)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	access := &http.Cookie{Name: "access_token", Value: result.AccessToken}
	refresh := &http.Cookie{Name: "refresh_token", Value: result.RefreshToken}
	return access, refresh
}

func TestRefreshHandlerSuccess(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	_, err := auth.Signup(context.Background(), db, auth.SignInSignUpParameters{
		Name:     "Refresh HTTP",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer db.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, email)

	_, refreshCookie := loginAndGetCookies(t, db, email, password)

	handler := RefreshHandler(db, testJWTSecret())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	req.AddCookie(refreshCookie)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp refreshResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if resp.Message == "" {
		t.Error("message must not be empty")
	}

	raw := rec.Body.String()
	if strings.Contains(raw, "access_token") {
		t.Error("JSON must not contain access_token")
	}
	if strings.Contains(raw, "refresh_token") {
		t.Error("JSON must not contain refresh_token")
	}

	newAccess := findCookie(rec.Result().Cookies(), "access_token")
	newRefresh := findCookie(rec.Result().Cookies(), "refresh_token")
	if newAccess == nil {
		t.Fatal("new access_token cookie must be set")
	}
	if newRefresh == nil {
		t.Fatal("new refresh_token cookie must be set")
	}
	if newRefresh.Value == refreshCookie.Value {
		t.Error("new refresh_token must differ from old")
	}

	claims, err := auth.VerifyAccessToken(testJWTSecret(), newAccess.Value)
	if err != nil {
		t.Fatalf("new access_token must be valid: %v", err)
	}
	if claims.UserID == "" {
		t.Error("new access token must have UserID")
	}
}

func TestRefreshHandlerMissingCookie(t *testing.T) {
	db := testDB(t)
	handler := RefreshHandler(db, testJWTSecret())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestRefreshHandlerInvalidToken(t *testing.T) {
	db := testDB(t)
	handler := RefreshHandler(db, testJWTSecret())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "invalid-token"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestRefreshHandlerWrongMethod(t *testing.T) {
	db := testDB(t)
	handler := RefreshHandler(db, testJWTSecret())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/refresh", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestRefreshHandlerOldTokenReusedFails(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	_, err := auth.Signup(context.Background(), db, auth.SignInSignUpParameters{
		Name:     "Replay Refresh",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer db.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, email)

	_, oldRefresh := loginAndGetCookies(t, db, email, password)

	handler := RefreshHandler(db, testJWTSecret())

	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	req1.AddCookie(oldRefresh)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("first refresh failed: %d", rec1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	req2.AddCookie(oldRefresh)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for reused token, got %d", rec2.Code)
	}
}
