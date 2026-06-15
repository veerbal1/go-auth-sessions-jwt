# Auth Lab

A production-grade authentication system built in Go — server-side sessions, short-lived JWTs, hashed refresh tokens, rotation with reuse detection, session revocation, role-based access control, and a full audit trail.

## Overview

Real auth systems need to answer hard questions: is this session still valid? Was this refresh token stolen and replayed? Can this user access this route? How do we revoke access? What happened in this security event? Auth Lab answers all of them — with integration tests against a real Postgres database.

## Quick Highlights

- **Passwords**: bcrypt-hashed, never stored as plaintext
- **Access tokens**: short-lived JWT (15 min), HttpOnly cookies, verified on every request
- **Refresh tokens**: SHA-256 hashed in DB, single-use, rotated on each use
- **Reuse detection**: atomic `used_at` check; replay revokes the entire session and token family
- **Server-side sessions**: Postgres-backed, revocable at any time
- **RBAC**: `user` and `admin` roles, enforced by middleware on every request
- **Audit trail**: every auth event logged — signup, login success/failure, refresh rotation, reuse detected, logout, access denied
- **Security alerts**: login queues a new-session email via an outbox pattern (no blocking I/O)
- **Route protection**: middleware stack — `RequireAuth` → `RequireRole("admin")` → handler
- **Integration tested**: every DB function tested against real Postgres

## Architecture

```
Client
  │
  ├── POST /api/v1/signup   → validate → bcrypt → insert user + assign role
  ├── POST /api/v1/login    → verify password → create session → create refresh token
  │                          → queue email alert → sign JWT → set HttpOnly cookies
  ├── POST /api/v1/refresh  → validate refresh token → rotate → new JWT + new refresh token
  ├── POST /api/v1/logout   → revoke session + tokens → clear cookies
  ├── GET  /api/v1/me       → [RequireAuth] → return user info + roles
  └── GET  /admin/users     → [RequireAuth] → [RequireRole("admin")] → list all users

Postgres (source of truth): users, roles, sessions, refresh tokens, audit events, email outbox
Redis (optional): rate-limiting counters, session cache
```

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Go 1.26 |
| Database | PostgreSQL 16 |
| Migrations | golang-migrate |
| Password hashing | golang.org/x/crypto/bcrypt |
| JWT | golang-jwt/jwt/v5 (HS256) |
| Refresh token hashing | crypto/sha256 |
| Testing | Go standard library + httptest + real Postgres |

## API Reference

All routes live under `/api/v1`. Protected routes use HttpOnly cookies (browser) or Bearer tokens (mobile/CLI).

### Public

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/signup` | Create account. Body: `{name, email, password}` → 201 |
| `POST` | `/api/v1/login` | Authenticate. Body: `{email, password}` → 200 + sets cookies |
| `POST` | `/api/v1/refresh` | Rotate tokens. Reads `refresh_token` cookie → 200 + new cookies |

### Protected (RequireAuth)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/me` | Current user. Returns `{user_id, name, email, session_id, roles}` |
| `POST` | `/api/v1/logout` | Revoke session, clear cookies |

### Admin (RequireAuth + RequireRole("admin"))

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/admin/users` | List all users with roles and disabled status |

### Error Responses

All errors return `{"error": "message"}` with appropriate HTTP status:
- `400` — validation error
- `401` — unauthenticated
- `403` — insufficient role
- `409` — conflict (duplicate email)
- `405` — wrong method

## Database Schema

```
users           (id, name, email, hashed_password, disabled_at, created_at, updated_at)
roles           (id, name, created_at)
user_roles      (id, user_id → users, role_id → roles)
sessions        (id, user_id → users, created_at, expires_at, revoked_at, revoke_reason, last_used_at, user_agent, ip_hash)
refresh_tokens  (id, session_id → sessions, token_hash, created_at, expires_at, used_at, revoked_at, replaced_by_token_id → self, revoke_reason)
audit_events    (id, event_type, user_id → users, session_id → sessions, request_id, ip_hash, user_agent, metadata JSONB, created_at)
email_outbox    (id, user_id → users, recipient_email, subject, body, status, attempt_count, next_attempt_at, sent_at, last_error, created_at, updated_at)
```

Key design choices:
- `audit_events` uses `ON DELETE SET NULL` — evidence survives user/session deletion
- `user_roles` has indexes on both foreign keys for role-based lookups
- `refresh_tokens` self-references `replaced_by_token_id` to model token family chains

## Auth Lifecycle

```
signup  →  login  →  session created  →  JWT issued  →  /me accessible
                                    →  refresh token issued (hash stored)
                                    →  email alert queued

refresh →  old token marked used  →  new token chained  →  new JWT
        →  replayed old token detected  →  session + family revoked

logout  →  session revoked  →  all refresh tokens revoked  →  cookies cleared
```

## Security Model

### Threat Defenses

| Threat | Defense | Limitation |
|---|---|---|
| Stolen password | Bcrypt; plaintext never stored | No 2FA yet |
| Stolen access token | 15-min JWT; RequireAuth checks DB session every request | External JWT consumers skip DB check |
| Stolen refresh token | Single-use rotation; reuse revokes entire family | Window exists between theft and rotation |
| Refresh replay attack | Atomic `used_at` check in guarded UPDATE | Race window is small but non-zero |
| Session revocation bypass | `revoked_at` checked on every protected request | Depends on RequireAuth wrapping all routes |
| Privilege escalation | `RequireRole` loads roles from DB per request; 403 | Coarse user/admin RBAC only |
| Disabled user access | `disabled_at` checked in login, refresh, and every request | No bulk session-revoke-on-disable |
| Brute-force login | Full audit trail; rate-limit design ready for Redis | Rate limiting not yet implemented |

### Rate Limiting (Designed, Not Yet Implemented)

Three Redis-backed counters with configurable TTLs:

| Key | What It Protects | Action on Exceed |
|---|---|---|
| `login:email:<hash>` | One account from password guessing | Block that email |
| `login:ip:<hash>` | The service from one IP | Block that IP |
| `login:email_ip:<hash>` | Targeted attack on one account | Block that pair |

Redis handles temporary rate limiting. Postgres `audit_events` provides permanent, immutable security history — even if Redis is flushed.

## Quick Start

```bash
# Start Postgres
docker compose up -d

# Run migrations
migrate -path migrations -database "postgres://auth_user:auth_password@localhost:5433/auth_db?sslmode=disable" up

# Run the server
DATABASE_URL="postgres://auth_user:auth_password@localhost:5433/auth_db?sslmode=disable" \
JWT_SECRET="your-secret-here" \
go run .

# Sign up
curl -X POST localhost:8080/api/v1/signup \
  -H "Content-Type: application/json" \
  -d '{"name":"Alice","email":"alice@example.com","password":"password123"}'

# Login
curl -i -X POST localhost:8080/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"password123"}'

# Run tests
DATABASE_URL="postgres://auth_user:auth_password@localhost:5433/auth_db?sslmode=disable" \
go test -count=1 ./...
```

## Project Structure

```
├── main.go              Entry point, server setup, route registration
├── auth/                Business logic (no HTTP)
│   ├── signup.go        Input validation, password hashing
│   ├── login.go         Login validation
│   ├── password.go      Bcrypt hash/verify
│   ├── db.go            Signup, Login, Session, RevokeSession, LoadUserRoles
│   ├── jwt.go           JWT generation and verification
│   ├── refresh.go       Refresh token generation, validation, rotation
│   ├── audit.go         WriteAuditEvent helper
│   ├── outbox.go        Email alert queue
│   └── errors.go        Typed errors (Validation, Conflict, Authentication)
├── api/                 HTTP layer (no raw SQL)
│   ├── signup.go        POST /api/v1/signup
│   ├── login.go         POST /api/v1/login
│   ├── refresh.go       POST /api/v1/refresh
│   ├── logout.go        POST /api/v1/logout
│   ├── me.go            GET /api/v1/me
│   ├── admin.go         GET /api/v1/admin/users
│   ├── middleware.go    RequireAuth, RequireRole
│   └── context.go       UserInfo, SetUser/GetUser
├── migrations/          Database migrations (golang-migrate)
└── docker-compose.yml   Postgres 16
```
