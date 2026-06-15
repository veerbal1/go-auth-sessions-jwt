# Stage 04 - Auth Sessions JWT

## Goal

Build `auth-lab`: a production-style local authentication system in Go.

This project models auth as a lifecycle, not a login endpoint:

```text
signup
-> login
-> server-side session
-> short-lived JWT access token
-> hashed refresh-token family
-> refresh-token rotation
-> reuse detection
-> logout/revocation
-> RBAC
-> audit trail
```

Stage 04 is split into two parts:

- Stage 04A: Postgres-backed auth correctness.
- Stage 04B: Redis hardening after Stage 04A tests pass.

Postgres is the source of truth. Redis is a speed/protection layer, not the foundation.

## Why This Matters For Go Backend/Platform Jobs

Real backend systems need to know:

- who the user is
- whether their session is still valid
- whether their token was stolen or reused
- whether they can access a protected route
- how to revoke access
- how to record security-sensitive events
- how to slow abuse without making the database the hot path

A simple "login gives JWT" project is not enough. This project should prove that the auth lifecycle is correct under failure and security edge cases.

## Concepts Practiced

- Password hashing with a trusted library
- Server-side sessions
- JWT access tokens
- Refresh tokens stored only as hashes
- Refresh-token families
- Token rotation and reuse detection
- Logout and session revocation
- RBAC v1 with `user` and `admin`
- Auth and role middleware
- Audit events
- Login security alert outbox
- Abuse-limit design
- Redis hardening after Postgres correctness
- Integration tests against Postgres

## Stage 04A - Postgres Auth Correctness

Build this first. Do not add Redis until these invariants pass.

### Threat Model v1


| Threat                         | Defense                                                                                                                             | Remaining Limitation                                                                                                |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Stolen password                | Bcrypt hashing; plaintext never stored                                                                                              | Weak passwords still crackable offline; no 2FA                                                                      |
| Stolen access token            | Short-lived JWT (15 min); HttpOnly cookie; RequireAuth checks DB session on every request                                           | JWT signature remains cryptographically valid until expiry; external JWT-only consumers would not see DB revocation |
| Stolen refresh token           | Single-use rotation; reuse detection revokes entire session/token family                                                            | Window between theft and rotation still open until legitimate client rotates                                        |
| Refresh-token replay           | Guarded UPDATE checks `used_at IS NULL` atomically; second caller triggers revocation of session + all tokens                       | Concurrent race before first rotation is still small but non-zero                                                   |
| Logout/session revocation      | Server-side `revoked_at` timestamp on session + all associated refresh tokens; cookies cleared; RequireAuth checks DB every request | Depends on every protected route using RequireAuth; external JWT-only consumers would not see DB revocation         |
| Normal user trying admin route | `RequireRole("admin")` middleware loads roles from DB each request; returns 403; audit event written                                | Only coarse user/admin RBAC exists; no fine-grained permissions yet                                                 |
| Disabled user                  | `disabled_at` checked in Login, RequireAuth, and refresh flows each request; generic error returned                                 | No automatic "revoke all sessions on disable" helper yet; must revoke separately                                    |
| Brute-force login attempts     | `auth.login_failed` audit in Postgres; abuse-limit design documented for Redis layer (Stage 04B)                                    | No rate limiting yet in Stage 04A; only detectable after the fact via audit trail                                   |


### Schema Plan

Plan migrations for:

- `users`
- `roles`
- `user_roles`
- `sessions`
- `refresh_tokens`
- `audit_events`
- `email_outbox`

### Build Tasks

1. Create threat model v1.
2. Create migrations.
3. Add config and DB connection.
4. Implement signup with password hashing.
5. Implement login that creates a server-side session.
6. Queue a new-login security email in `email_outbox`.
7. Issue a short-lived JWT access token, target lifetime around 15 minutes.
8. Issue a longer-lived refresh token, target lifetime around 7-30 days, storing only its hash.
9. Add `RequireAuth` middleware.
10. Add `GET /me`.
11. Add refresh-token rotation.
12. Add refresh-token reuse detection that revokes the session/token family.
13. Add logout.
14. Add RBAC v1: `user` and `admin`.
15. Add `RequireRole("admin")`.
16. Add `GET /admin/users`.
17. Add audit events.
18. Document abuse-limit design.

### Security Invariants To Test

- Plaintext passwords are never stored.
- Raw refresh tokens are never stored.
- Login creates a server-side session.
- Login queues exactly one new-login alert.
- Login alert body contains no password, password hash, raw refresh token, or reset token.
- Unauthenticated requests cannot access `GET /me`.
- Normal users cannot access `GET /admin/users`.
- Refresh tokens are single-use.
- Refresh rotation links old and new tokens in one token family.
- Reused refresh token revokes the session/token family.
- Logout prevents further refresh.
- Important auth events create audit records.

## Stage 04B - Redis Auth Hardening

Start this only after Stage 04A works and tests pass.

### Redis Responsibilities

Redis is for fast temporary state:

- login abuse-limit counters
- optional active-session cache later

Postgres remains permanent truth for:

- users
- sessions
- refresh tokens
- roles
- audit events

### Redis Build Tasks

1. Add Redis as a local dependency.
2. Add login failure counters with TTLs.
3. Use separate keys for:
  - email hash
  - IP hash
  - email hash + IP hash
4. Keep long-term audit history in Postgres.
5. Optional: add active-session cache.
6. On logout/revocation, update Postgres first, then delete Redis session cache key.

### Abuse-Limit Design

Three rate-limit keys, all stored in Redis with TTLs:


| Key                     | Counts                            | Why                                                 | TTL                               | Exceeded                                              |
| ----------------------- | --------------------------------- | --------------------------------------------------- | --------------------------------- | ----------------------------------------------------- |
| `login:email:<hash>`    | Failed attempts per account       | Protects one account from password guessing         | Resets after window (e.g. 15 min) | Block logins for that email until TTL expires         |
| `login:ip:<hash>`       | Failed attempts per IP            | Protects the service from one abusive source        | Resets after window (e.g. 15 min) | Block all logins from that IP until TTL expires       |
| `login:email_ip:<hash>` | Failed attempts per email+IP pair | Catches one source attacking one account repeatedly | Resets after window (e.g. 15 min) | Block logins for that email+IP pair until TTL expires |


Redis counters are temporary rate-limiting state. Postgres `audit_events` keeps permanent, immutable evidence of every `auth.login_failed` — Redis can be flushed without losing security history.

## API Shape

Expected routes:

- `POST /api/v1/signup`
- `POST /api/v1/login`
- `POST /api/v1/refresh`
- `POST /api/v1/logout`
- `GET /api/v1/me`
- `GET /api/v1/admin/users`

Exact request/response JSON can evolve as each slice is built.

## Done Checklist

- [x] README and threat model v1 exist.
- [x] Migrations run from empty database.
- [x] Signup works.
- [x] Login works and creates a session.
- [x] New-login alert is queued in `email_outbox`.
- [x] Access token is short-lived.
- [x] Refresh token is stored only as a hash.
- [x] Refresh token family is modeled.
- [x] Refresh rotation works.
- [x] Refresh reuse detection revokes the session/token family.
- [x] Logout invalidates server-side state.
- [x] `GET /me` requires auth.
- [x] `GET /admin/users` requires admin role.
- [x] Audit events exist for sensitive auth actions.
- [x] Abuse-limit design is documented.
- [x] Stage 04A tests pass.
- [ ] Stage 04B Redis hardening is added after Stage 04A, or explicitly deferred.

## First Tiny Task

Create the Go module for this folder, then pause before writing handlers.

After that, design the first migration tables in this order:

1. `users`
2. `roles`
3. `user_roles`

Do not write implementation handlers until the schema is reviewed.