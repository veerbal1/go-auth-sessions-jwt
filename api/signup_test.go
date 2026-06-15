package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestSignupHandlerSuccess(t *testing.T) {
	db := testDB(t)
	handler := SignupHandler(db)

	email := uniqueEmail()
	body := fmt.Sprintf(`{"name":"Alice","email":"%s","password":"password123"}`, email)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/signup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp signupResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.ID == "" {
		t.Error("id must not be empty")
	}
	if resp.Name != "Alice" {
		t.Errorf("name = %q, want %q", resp.Name, "Alice")
	}
	if resp.Email != email {
		t.Errorf("email = %q, want %q", resp.Email, email)
	}

	raw := rec.Body.String()
	if strings.Contains(raw, "password") {
		t.Error("response must not include password")
	}

	db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, resp.ID)
}

func TestSignupHandlerInvalidJSON(t *testing.T) {
	db := testDB(t)
	handler := SignupHandler(db)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/signup", strings.NewReader(`not json`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestSignupHandlerWrongMethod(t *testing.T) {
	db := testDB(t)
	handler := SignupHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/signup", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestSignupHandlerEmptyName(t *testing.T) {
	db := testDB(t)
	handler := SignupHandler(db)

	body := `{"name":"","email":"alice@example.com","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/signup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestSignupHandlerShortPassword(t *testing.T) {
	db := testDB(t)
	handler := SignupHandler(db)

	email := uniqueEmail()
	body := fmt.Sprintf(`{"name":"Alice","email":"%s","password":"short"}`, email)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/signup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestSignupHandlerDuplicateEmail(t *testing.T) {
	db := testDB(t)
	handler := SignupHandler(db)

	email := uniqueEmail()
	body := fmt.Sprintf(`{"name":"Alice","email":"%s","password":"password123"}`, email)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/signup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("first signup failed: %d %s", rec.Code, rec.Body.String())
	}

	var first signupResponse
	json.NewDecoder(rec.Body).Decode(&first)
	defer db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, first.ID)

	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/signup", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", rec2.Code)
	}
}
