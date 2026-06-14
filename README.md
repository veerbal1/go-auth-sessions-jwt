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

- [ ] README and threat model v1 exist.
- [ ] Migrations run from empty database.
- [ ] Signup works.
- [ ] Login works and creates a session.
- [ ] New-login alert is queued in `email_outbox`.
- [ ] Access token is short-lived.
- [ ] Refresh token is stored only as a hash.
- [ ] Refresh token family is modeled.
- [ ] Refresh rotation works.
- [ ] Refresh reuse detection revokes the session/token family.
- [ ] Logout invalidates server-side state.
- [ ] `GET /me` requires auth.
- [ ] `GET /admin/users` requires admin role.
- [ ] Audit events exist for sensitive auth actions.
- [ ] Abuse-limit design is documented.
- [ ] Stage 04A tests pass.
- [ ] Stage 04B Redis hardening is added after Stage 04A, or explicitly deferred.

## Public Posting Ideas

```text
Week 07 of becoming a Go backend/platform engineer.

Built:
- A production-style local auth system in Go.
- Users, roles, sessions, new-login security alerts, short-lived JWT access tokens, hashed refresh-token families, token rotation, reuse detection, RBAC route protection, and audit logs.

Learned:
- Auth is a lifecycle, not just a login endpoint.
- Postgres is the source of truth.
- Redis belongs later as a speed/protection layer.

Hard part:
- Modelling refresh token rotation cleanly: old token used once, new token linked into the same token family, replay detected later, then the session is revoked.
```

## First Tiny Task

Create the Go module for this folder, then pause before writing handlers.

After that, design the first migration tables in this order:

1. `users`
2. `roles`
3. `user_roles`

Do not write implementation handlers until the schema is reviewed.
