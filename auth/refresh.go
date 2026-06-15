package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

const rawTokenBytes = 32

func GenerateRefreshToken() (string, error) {
	b := make([]byte, rawTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func HashRefreshToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

type CreatedRefreshToken struct {
	ID        string
	RawToken  string
	ExpiresAt time.Time
}

func CreateRefreshToken(ctx context.Context, db Querier, sessionID string, lifetime time.Duration) (CreatedRefreshToken, error) {
	raw, err := GenerateRefreshToken()
	if err != nil {
		return CreatedRefreshToken{}, err
	}

	tokenHash := HashRefreshToken(raw)
	expiresAt := time.Now().Add(lifetime)

	var id string
	err = db.QueryRowContext(ctx,
		`INSERT INTO refresh_tokens (session_id, token_hash, expires_at)
		 VALUES ($1, $2, $3) RETURNING id`,
		sessionID, tokenHash, expiresAt,
	).Scan(&id)
	if err != nil {
		return CreatedRefreshToken{}, fmt.Errorf("failed to insert refresh token: %w", err)
	}

	return CreatedRefreshToken{
		ID:        id,
		RawToken:  raw,
		ExpiresAt: expiresAt,
	}, nil
}

type ValidatedRefreshToken struct {
	TokenID   string
	SessionID string
	UserID    string
	Name      string
	Email     string
}

func ValidateRefreshToken(ctx context.Context, db *sql.DB, rawToken string) (ValidatedRefreshToken, error) {
	tokenHash := HashRefreshToken(rawToken)

	var tokenID, sessionID, userID, name, email string
	var tokenExpiresAt, tokenUsedAt, tokenRevokedAt sql.NullTime
	var sessionExpiresAt, sessionRevokedAt sql.NullTime
	var userDisabledAt sql.NullTime

	err := db.QueryRowContext(ctx,
		`SELECT rt.id, rt.session_id, rt.expires_at, rt.used_at, rt.revoked_at,
		        s.user_id, s.expires_at, s.revoked_at,
		        u.name, u.email, u.disabled_at
		 FROM refresh_tokens rt
		 JOIN sessions s ON s.id = rt.session_id
		 JOIN users u ON u.id = s.user_id
		 WHERE rt.token_hash = $1`,
		tokenHash,
	).Scan(&tokenID, &sessionID, &tokenExpiresAt, &tokenUsedAt, &tokenRevokedAt,
		&userID, &sessionExpiresAt, &sessionRevokedAt,
		&name, &email, &userDisabledAt)
	if err == sql.ErrNoRows {
		return ValidatedRefreshToken{}, NewAuthenticationError("invalid refresh token")
	}
	if err != nil {
		return ValidatedRefreshToken{}, fmt.Errorf("failed to find refresh token: %w", err)
	}

	if tokenRevokedAt.Valid {
		return ValidatedRefreshToken{}, NewAuthenticationError("invalid refresh token")
	}

	if tokenExpiresAt.Valid && tokenExpiresAt.Time.Before(time.Now()) {
		return ValidatedRefreshToken{}, NewAuthenticationError("invalid refresh token")
	}

	if sessionRevokedAt.Valid {
		return ValidatedRefreshToken{}, NewAuthenticationError("invalid refresh token")
	}

	if sessionExpiresAt.Valid && sessionExpiresAt.Time.Before(time.Now()) {
		return ValidatedRefreshToken{}, NewAuthenticationError("invalid refresh token")
	}

	if userDisabledAt.Valid {
		return ValidatedRefreshToken{}, NewAuthenticationError("invalid refresh token")
	}

	return ValidatedRefreshToken{
		TokenID:   tokenID,
		SessionID: sessionID,
		UserID:    userID,
		Name:      name,
		Email:     email,
	}, nil
}

type RotatedTokens struct {
	RefreshToken     string
	RefreshExpiresAt time.Time
	AccessToken      string
}

func RotateRefreshToken(ctx context.Context, db *sql.DB, rawToken string, jwtSecret []byte, accessLifetime, refreshLifetime time.Duration) (RotatedTokens, error) {
	validated, err := ValidateRefreshToken(ctx, db, rawToken)
	if err != nil {
		return RotatedTokens{}, err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return RotatedTokens{}, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		`UPDATE refresh_tokens
		 SET used_at = now()
		 WHERE id = $1
		   AND used_at IS NULL
		   AND revoked_at IS NULL
		   AND replaced_by_token_id IS NULL`,
		validated.TokenID,
	)
	if err != nil {
		return RotatedTokens{}, fmt.Errorf("failed to mark token as used: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return RotatedTokens{}, fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows != 1 {
		if _, auditErr := WriteAuditEvent(ctx, tx, AuditEventInput{
			EventType: "auth.refresh_reuse_detected",
			UserID:    validated.UserID,
			SessionID: validated.SessionID,
		}); auditErr != nil {
			return RotatedTokens{}, fmt.Errorf("failed to write reuse audit: %w", auditErr)
		}

		if _, execErr := tx.ExecContext(ctx,
			`UPDATE sessions SET revoked_at = now(), revoke_reason = 'refresh_reuse' WHERE id = $1`,
			validated.SessionID,
		); execErr != nil {
			return RotatedTokens{}, fmt.Errorf("failed to revoke session: %w", execErr)
		}

		if _, execErr := tx.ExecContext(ctx,
			`UPDATE refresh_tokens SET revoked_at = now(), revoke_reason = 'refresh_reuse'
			 WHERE session_id = $1 AND revoked_at IS NULL`,
			validated.SessionID,
		); execErr != nil {
			return RotatedTokens{}, fmt.Errorf("failed to revoke refresh tokens: %w", execErr)
		}

		if commitErr := tx.Commit(); commitErr != nil {
			return RotatedTokens{}, fmt.Errorf("failed to commit revocation: %w", commitErr)
		}

		return RotatedTokens{}, NewAuthenticationError("invalid refresh token")
	}

	newRaw, err := GenerateRefreshToken()
	if err != nil {
		return RotatedTokens{}, err
	}
	newHash := HashRefreshToken(newRaw)
	newExpiresAt := time.Now().Add(refreshLifetime)

	var newTokenID string
	err = tx.QueryRowContext(ctx,
		`INSERT INTO refresh_tokens (session_id, token_hash, expires_at)
		 VALUES ($1, $2, $3) RETURNING id`,
		validated.SessionID, newHash, newExpiresAt,
	).Scan(&newTokenID)
	if err != nil {
		return RotatedTokens{}, fmt.Errorf("failed to create new refresh token: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`UPDATE refresh_tokens SET replaced_by_token_id = $1 WHERE id = $2`,
		newTokenID, validated.TokenID,
	)
	if err != nil {
		return RotatedTokens{}, fmt.Errorf("failed to link tokens: %w", err)
	}

	if _, err := WriteAuditEvent(ctx, tx, AuditEventInput{
		EventType: "auth.refresh_rotated",
		UserID:    validated.UserID,
		SessionID: validated.SessionID,
	}); err != nil {
		return RotatedTokens{}, fmt.Errorf("failed to write audit event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return RotatedTokens{}, fmt.Errorf("failed to commit rotation: %w", err)
	}

	newAccessToken, err := GenerateAccessToken(jwtSecret, validated.UserID, validated.SessionID, accessLifetime)
	if err != nil {
		return RotatedTokens{}, fmt.Errorf("failed to generate access token: %w", err)
	}

	return RotatedTokens{
		RefreshToken:     newRaw,
		RefreshExpiresAt: newExpiresAt,
		AccessToken:      newAccessToken,
	}, nil
}
