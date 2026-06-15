package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AccessTokenClaims struct {
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
	jwt.RegisteredClaims
}

func GenerateAccessToken(secret []byte, userID, sessionID string, lifetime time.Duration) (string, error) {
	now := time.Now()
	claims := AccessTokenClaims{
		UserID:    userID,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(lifetime)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return signed, nil
}

func hmacKeyFunc(secret []byte) jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	}
}

func VerifyAccessToken(secret []byte, tokenString string) (*AccessTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AccessTokenClaims{}, hmacKeyFunc(secret))
	if err != nil {
		return nil, fmt.Errorf("invalid access token: %w", err)
	}

	claims, ok := token.Claims.(*AccessTokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid access token claims")
	}

	return claims, nil
}
