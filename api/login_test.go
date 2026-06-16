package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/veerbal1/go-auth-sessions-jwt/auth"
)

func testJWTSecret() []byte {
	return []byte("test-jwt-secret")
}

func TestLoginHandlerSuccess(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	_, err := auth.Signup(context.Background(), db, auth.SignInSignUpParameters{
		Name:     "Login HTTP Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	handler := LoginHandler(db, testJWTSecret())

	body := fmt.Sprintf(`{"email":"%s","password":"%s"}`, email, password)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp loginResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.UserID == "" {
		t.Error("UserID must not be empty")
	}
	if resp.Name != "Login HTTP Test" {
		t.Errorf("Name = %q, want %q", resp.Name, "Login HTTP Test")
	}
	if resp.SessionID == "" {
		t.Error("SessionID must not be empty")
	}

	raw := rec.Body.String()
	if strings.Contains(strings.ToLower(raw), "password") {
		t.Error("response must not contain password")
	}
	if strings.Contains(raw, "access_token") {
		t.Error("response JSON must not contain access_token")
	}
	if strings.Contains(raw, "refresh_token") {
		t.Error("response JSON must not contain refresh_token")
	}

	accessCookie := findCookie(rec.Result().Cookies(), "access_token")
	if accessCookie == nil {
		t.Fatal("access_token cookie must be set")
	}
	if !accessCookie.HttpOnly {
		t.Error("access_token cookie must be HttpOnly")
	}
	if accessCookie.Value == "" {
		t.Error("access_token cookie value must not be empty")
	}

	refreshCookie := findCookie(rec.Result().Cookies(), "refresh_token")
	if refreshCookie == nil {
		t.Fatal("refresh_token cookie must be set")
	}
	if !refreshCookie.HttpOnly {
		t.Error("refresh_token cookie must be HttpOnly")
	}
	if refreshCookie.Value == "" {
		t.Error("refresh_token cookie value must not be empty")
	}
	if refreshCookie.Path != "/api/v1/refresh" {
		t.Errorf("refresh_token Path = %q, want %q", refreshCookie.Path, "/api/v1/refresh")
	}

	claims, err := auth.VerifyAccessToken(testJWTSecret(), accessCookie.Value)
	if err != nil {
		t.Fatalf("access token cookie must be a valid JWT: %v", err)
	}
	if claims.UserID != resp.UserID {
		t.Errorf("JWT UserID = %q, want %q", claims.UserID, resp.UserID)
	}

	db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, resp.UserID)
}

func TestLoginHandlerWrongPassword(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	_, err := auth.Signup(context.Background(), db, auth.SignInSignUpParameters{
		Name:     "WrongPass HTTP",
		Email:    email,
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	handler := LoginHandler(db, testJWTSecret())

	body := fmt.Sprintf(`{"email":"%s","password":"wrongpass"}`, email)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}

	if findCookie(rec.Result().Cookies(), "access_token") != nil {
		t.Error("must not set access_token cookie on failed login")
	}
}

func TestLoginHandlerInvalidJSON(t *testing.T) {
	db := testDB(t)
	handler := LoginHandler(db, testJWTSecret())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(`not json`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestLoginHandlerEmptyEmail(t *testing.T) {
	db := testDB(t)
	handler := LoginHandler(db, testJWTSecret())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(`{"email":"","password":"password123"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestLoginHandlerWrongMethod(t *testing.T) {
	db := testDB(t)
	handler := LoginHandler(db, testJWTSecret())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/login", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}
