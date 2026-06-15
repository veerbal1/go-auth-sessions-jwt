package auth

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"
)

type Querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type CreatedUser struct {
	ID    string
	Name  string
	Email string
}

func Signup(ctx context.Context, db *sql.DB, in SignInSignUpParameters) (CreatedUser, error) {
	prepared, err := PrepareSignup(in)
	if err != nil {
		return CreatedUser{}, err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return CreatedUser{}, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var userID string
	err = tx.QueryRowContext(ctx,
		`INSERT INTO users (name, email, hashed_password) VALUES ($1, $2, $3) RETURNING id`,
		prepared.Name, prepared.Email, prepared.HashedPassword,
	).Scan(&userID)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return CreatedUser{}, NewConflictError("email already registered")
		}
		return CreatedUser{}, fmt.Errorf("failed to insert user: %w", err)
	}

	var roleID string
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM roles WHERE name = 'user'`,
	).Scan(&roleID)
	if err != nil {
		return CreatedUser{}, fmt.Errorf("failed to find user role: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`,
		userID, roleID,
	)
	if err != nil {
		return CreatedUser{}, fmt.Errorf("failed to assign role: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return CreatedUser{}, fmt.Errorf("failed to commit transaction: %w", err)
	}

	WriteAuditEvent(ctx, db, AuditEventInput{
		EventType: "user.signup",
		UserID:    userID,
	})

	return CreatedUser{
		ID:    userID,
		Name:  prepared.Name,
		Email: prepared.Email,
	}, nil
}

func Login(ctx context.Context, db *sql.DB, in LoginInput) (CreatedUser, error) {
	validated, err := ValidateLogin(in)
	if err != nil {
		return CreatedUser{}, err
	}

	var user CreatedUser
	var hashedPassword string
	var disabledAt sql.NullTime

	err = db.QueryRowContext(ctx,
		`SELECT id, name, email, hashed_password, disabled_at FROM users WHERE email = $1`,
		validated.Email,
	).Scan(&user.ID, &user.Name, &user.Email, &hashedPassword, &disabledAt)
	if err == sql.ErrNoRows {
		WriteAuditEvent(ctx, db, AuditEventInput{
			EventType: "auth.login_failed",
			Metadata:  map[string]any{"email": validated.Email},
		})
		return CreatedUser{}, NewAuthenticationError("invalid email or password")
	}
	if err != nil {
		return CreatedUser{}, fmt.Errorf("failed to find user: %w", err)
	}

	if disabledAt.Valid {
		WriteAuditEvent(ctx, db, AuditEventInput{
			EventType: "auth.login_failed",
			UserID:    user.ID,
		})
		return CreatedUser{}, NewAuthenticationError("invalid email or password")
	}

	if !VerifyPassword(hashedPassword, validated.Password) {
		WriteAuditEvent(ctx, db, AuditEventInput{
			EventType: "auth.login_failed",
			UserID:    user.ID,
		})
		return CreatedUser{}, NewAuthenticationError("invalid email or password")
	}

	return user, nil
}

type CreatedSession struct {
	ID        string
	ExpiresAt time.Time
}

func CreateSession(ctx context.Context, db Querier, userID string, lifetime time.Duration, userAgent, ipHash string) (CreatedSession, error) {
	expiresAt := time.Now().Add(lifetime)

	var sessionID string
	err := db.QueryRowContext(ctx,
		`INSERT INTO sessions (user_id, expires_at, user_agent, ip_hash)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		userID, expiresAt, userAgent, ipHash,
	).Scan(&sessionID)
	if err != nil {
		return CreatedSession{}, fmt.Errorf("failed to create session: %w", err)
	}

	return CreatedSession{
		ID:        sessionID,
		ExpiresAt: expiresAt,
	}, nil
}

type LoginWithSessionResult struct {
	UserID    string
	Name      string
	Email     string
	SessionID string
	ExpiresAt time.Time
}

func LoginWithSession(ctx context.Context, db *sql.DB, in LoginInput, lifetime time.Duration, userAgent, ipHash string) (LoginWithSessionResult, error) {
	user, err := Login(ctx, db, in)
	if err != nil {
		return LoginWithSessionResult{}, err
	}

	session, err := CreateSession(ctx, db, user.ID, lifetime, userAgent, ipHash)
	if err != nil {
		return LoginWithSessionResult{}, fmt.Errorf("failed to create session: %w", err)
	}

	return LoginWithSessionResult{
		UserID:    user.ID,
		Name:      user.Name,
		Email:     user.Email,
		SessionID: session.ID,
		ExpiresAt: session.ExpiresAt,
	}, nil
}

type LoginResult struct {
	UserID           string
	Name             string
	Email            string
	SessionID        string
	SessionExpiresAt time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
	AccessToken      string
}

func LoginWithRefreshToken(ctx context.Context, db *sql.DB, in LoginInput, jwtSecret []byte, sessionLifetime, refreshLifetime, accessLifetime time.Duration, userAgent, ipHash string) (LoginResult, error) {
	user, err := Login(ctx, db, in)
	if err != nil {
		return LoginResult{}, err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return LoginResult{}, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	session, err := CreateSession(ctx, tx, user.ID, sessionLifetime, userAgent, ipHash)
	if err != nil {
		return LoginResult{}, fmt.Errorf("failed to create session: %w", err)
	}

	refresh, err := CreateRefreshToken(ctx, tx, session.ID, refreshLifetime)
	if err != nil {
		return LoginResult{}, fmt.Errorf("failed to create refresh token: %w", err)
	}

	if _, err := QueueNewLoginAlert(ctx, tx, user.ID, user.Email); err != nil {
		return LoginResult{}, fmt.Errorf("failed to queue email alert: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return LoginResult{}, fmt.Errorf("failed to commit transaction: %w", err)
	}

	WriteAuditEvent(ctx, db, AuditEventInput{
		EventType: "auth.login_success",
		UserID:    user.ID,
		SessionID: session.ID,
	})

	WriteAuditEvent(ctx, db, AuditEventInput{
		EventType: "auth.login_alert_queued",
		UserID:    user.ID,
		SessionID: session.ID,
	})

	accessToken, err := GenerateAccessToken(jwtSecret, user.ID, session.ID, accessLifetime)
	if err != nil {
		return LoginResult{}, fmt.Errorf("failed to generate access token: %w", err)
	}

	return LoginResult{
		UserID:           user.ID,
		Name:             user.Name,
		Email:            user.Email,
		SessionID:        session.ID,
		SessionExpiresAt: session.ExpiresAt,
		RefreshToken:     refresh.RawToken,
		RefreshExpiresAt: refresh.ExpiresAt,
		AccessToken:      accessToken,
	}, nil
}

func RevokeSession(ctx context.Context, db *sql.DB, sessionID string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = now(), revoke_reason = 'logout' WHERE id = $1`,
		sessionID,
	)
	if err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked_at = now(), revoke_reason = 'logout'
		 WHERE session_id = $1 AND revoked_at IS NULL`,
		sessionID,
	)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh tokens: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit revocation: %w", err)
	}

	return nil
}
