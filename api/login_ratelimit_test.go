package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/veerbal1/go-auth-sessions-jwt/auth"
)

var loginRateLimitIPSeq uint32

func testRedisClient(t *testing.T) *redis.Client {
	t.Helper()

	rdb := redis.NewClient(&redis.Options{Addr: testRedisAddr()})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("redis not available, skipping: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

func testRedisAddr() string {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		return "localhost:6379"
	}
	return addr
}

func uniqueLoginRateLimitIP() string {
	n := uint64(time.Now().UnixNano()) + uint64(atomic.AddUint32(&loginRateLimitIPSeq, 1))
	return fmt.Sprintf("203.0.%d.%d", n%250+1, (n/250)%250+1)
}

func loginRateLimitKeys(email, ip string) []string {
	keys := []string{auth.LoginEmailKey(email)}
	if ip != "" {
		keys = append(keys, auth.LoginIPKey(ip), auth.LoginEmailIPKey(email, ip))
	}
	return keys
}

func resetLoginRateLimitKeys(t *testing.T, rdb *redis.Client, email, ip string) {
	t.Helper()

	keys := loginRateLimitKeys(email, ip)
	if err := rdb.Del(context.Background(), keys...).Err(); err != nil {
		t.Fatalf("failed to reset rate-limit keys: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Del(context.Background(), keys...).Err() })
}

func performLogin(handler http.Handler, email, password, ip string) *httptest.ResponseRecorder {
	body := fmt.Sprintf(`{"email":"%s","password":"%s"}`, email, password)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if ip != "" {
		req.Header.Set("X-Forwarded-For", ip)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func requireRedisCounter(t *testing.T, rdb *redis.Client, key string, want int) {
	t.Helper()

	count, err := rdb.Get(context.Background(), key).Int()
	if err != nil {
		t.Fatalf("failed to read counter %q: %v", key, err)
	}
	if count != want {
		t.Fatalf("counter %q = %d, want %d", key, count, want)
	}
}

func requireMissingRedisKey(t *testing.T, rdb *redis.Client, key string) {
	t.Helper()

	count, err := rdb.Get(context.Background(), key).Int()
	if !errors.Is(err, redis.Nil) {
		t.Fatalf("counter %q should be deleted, got count=%d err=%v", key, count, err)
	}
}

func signupRateLimitUser(t *testing.T, name string) (string, string) {
	t.Helper()

	db := testDB(t)
	email := uniqueEmail()
	password := "password123"

	_, err := auth.Signup(context.Background(), db, auth.SignInSignUpParameters{
		Name:     name,
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, email) })

	return email, password
}

type redisCommandErrorHook struct {
	command string
	err     error
}

func (h redisCommandErrorHook) DialHook(next redis.DialHook) redis.DialHook {
	return next
}

func (h redisCommandErrorHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if strings.EqualFold(cmd.Name(), h.command) {
			return h.err
		}
		return next(ctx, cmd)
	}
}

func (h redisCommandErrorHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func TestLoginRateLimitWrongPasswordIncrementsRedisCounters(t *testing.T) {
	db := testDB(t)
	rdb := testRedisClient(t)

	email, _ := signupRateLimitUser(t, "RateLimit Fail")
	ip := uniqueLoginRateLimitIP()
	resetLoginRateLimitKeys(t, rdb, email, ip)

	handler := LoginHandler(db, testJWTSecret(), rdb)
	rec := performLogin(handler, email, "wrongpass", ip)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}

	for _, key := range loginRateLimitKeys(email, ip) {
		requireRedisCounter(t, rdb, key, 1)
	}
}

func TestLoginRateLimitBlocksSixthAttempt(t *testing.T) {
	db := testDB(t)
	rdb := testRedisClient(t)

	email, _ := signupRateLimitUser(t, "RateLimit Block")
	ip := uniqueLoginRateLimitIP()
	resetLoginRateLimitKeys(t, rdb, email, ip)

	handler := LoginHandler(db, testJWTSecret(), rdb)
	for i := 1; i <= auth.DefaultRateLimit; i++ {
		rec := performLogin(handler, email, "wrongpass", ip)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d: %s", i, rec.Code, rec.Body.String())
		}
	}

	rec := performLogin(handler, email, "wrongpass", ip)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("6th attempt: expected 429, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLoginRateLimitSuccessfulLoginClearsCounters(t *testing.T) {
	db := testDB(t)
	rdb := testRedisClient(t)

	email, password := signupRateLimitUser(t, "RateLimit Clear")
	ip := uniqueLoginRateLimitIP()
	resetLoginRateLimitKeys(t, rdb, email, ip)

	handler := LoginHandler(db, testJWTSecret(), rdb)
	for i := 1; i <= 3; i++ {
		rec := performLogin(handler, email, "wrongpass", ip)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d: %s", i, rec.Code, rec.Body.String())
		}
	}

	for _, key := range loginRateLimitKeys(email, ip) {
		requireRedisCounter(t, rdb, key, 3)
	}

	rec := performLogin(handler, email, password, ip)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	for _, key := range loginRateLimitKeys(email, ip) {
		requireMissingRedisKey(t, rdb, key)
	}
}

func TestLoginRateLimitWorksWithNilRedis(t *testing.T) {
	db := testDB(t)

	email, password := signupRateLimitUser(t, "NilRedis")
	handler := LoginHandler(db, testJWTSecret(), nil)

	rec := performLogin(handler, email, password, uniqueLoginRateLimitIP())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLoginRateLimitRecordFailureErrorReturns500(t *testing.T) {
	db := testDB(t)
	rdb := testRedisClient(t)

	email, _ := signupRateLimitUser(t, "RateLimit Record Error")
	ip := uniqueLoginRateLimitIP()
	resetLoginRateLimitKeys(t, rdb, email, ip)
	rdb.AddHook(redisCommandErrorHook{command: "incr", err: errors.New("incr failed")})

	handler := LoginHandler(db, testJWTSecret(), rdb)
	rec := performLogin(handler, email, "wrongpass", ip)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
	if findCookie(rec.Result().Cookies(), "access_token") != nil {
		t.Fatal("must not set access_token cookie when recording failure fails")
	}
}

func TestLoginRateLimitRecordSuccessErrorReturns500(t *testing.T) {
	db := testDB(t)
	cleanupRDB := testRedisClient(t)
	failingRDB := testRedisClient(t)

	email, password := signupRateLimitUser(t, "RateLimit Clear Error")
	ip := uniqueLoginRateLimitIP()
	resetLoginRateLimitKeys(t, cleanupRDB, email, ip)
	if err := auth.RecordLoginFailure(context.Background(), cleanupRDB, email, ip); err != nil {
		t.Fatalf("failed to seed rate-limit counters: %v", err)
	}
	failingRDB.AddHook(redisCommandErrorHook{command: "del", err: errors.New("del failed")})

	handler := LoginHandler(db, testJWTSecret(), failingRDB)
	rec := performLogin(handler, email, password, ip)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
	if findCookie(rec.Result().Cookies(), "access_token") != nil {
		t.Fatal("must not set access_token cookie when clearing counters fails")
	}

	var revokedAt sql.NullTime
	db.QueryRowContext(context.Background(),
		`SELECT s.revoked_at FROM sessions s
		 JOIN users u ON u.id = s.user_id
		 WHERE u.email = $1
		 ORDER BY s.created_at DESC LIMIT 1`,
		email,
	).Scan(&revokedAt)
	if !revokedAt.Valid {
		t.Fatal("session must be revoked when RecordLoginSuccess fails")
	}
}
