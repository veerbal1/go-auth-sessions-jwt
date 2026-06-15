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

func CreateRefreshToken(ctx context.Context, db *sql.DB, sessionID string, lifetime time.Duration) (CreatedRefreshToken, error) {
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
