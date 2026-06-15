package api

import (
	"database/sql"
	"net/http"
	"strings"
	"time"

	"auth-lab/auth"
)

func RequireAuth(db *sql.DB, jwtSecret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractToken(r)
			if token == "" {
				writeError(w, http.StatusUnauthorized, "missing access token")
				return
			}

			claims, err := auth.VerifyAccessToken(jwtSecret, token)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "invalid or expired access token")
				return
			}

			var sessionRevoked sql.NullTime
			var sessionExpires time.Time
			var name, email string

			err = db.QueryRowContext(r.Context(),
				`SELECT u.name, u.email, s.expires_at, s.revoked_at
				 FROM sessions s
				 JOIN users u ON u.id = s.user_id
				 WHERE s.id = $1 AND s.user_id = $2`,
				claims.SessionID, claims.UserID,
			).Scan(&name, &email, &sessionExpires, &sessionRevoked)
			if err == sql.ErrNoRows {
				writeError(w, http.StatusUnauthorized, "session not found")
				return
			}
			if err != nil {
				writeError(w, http.StatusInternalServerError, "internal error")
				return
			}

			if sessionRevoked.Valid {
				writeError(w, http.StatusUnauthorized, "session has been revoked")
				return
			}

			if sessionExpires.Before(time.Now()) {
				writeError(w, http.StatusUnauthorized, "session has expired")
				return
			}

			ctx := SetUser(r.Context(), UserInfo{
				UserID:    claims.UserID,
				Name:      name,
				Email:     email,
				SessionID: claims.SessionID,
			})

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func extractToken(r *http.Request) string {
	if cookie, err := r.Cookie("access_token"); err == nil {
		return cookie.Value
	}

	bearer := r.Header.Get("Authorization")
	if strings.HasPrefix(bearer, "Bearer ") {
		return strings.TrimPrefix(bearer, "Bearer ")
	}

	return ""
}
