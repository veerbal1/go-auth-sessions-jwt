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
			var userDisabled sql.NullTime
			var name, email string

			err = db.QueryRowContext(r.Context(),
				`SELECT u.name, u.email, s.expires_at, s.revoked_at, u.disabled_at
				 FROM sessions s
				 JOIN users u ON u.id = s.user_id
				 WHERE s.id = $1 AND s.user_id = $2`,
				claims.SessionID, claims.UserID,
			).Scan(&name, &email, &sessionExpires, &sessionRevoked, &userDisabled)
			if err == sql.ErrNoRows {
				if _, err := auth.WriteAuditEvent(r.Context(), db, auth.AuditEventInput{
					EventType: "auth.access_denied",
					UserID:    claims.UserID,
					SessionID: claims.SessionID,
					Metadata:  map[string]any{"reason": "session not found"},
				}); err != nil {
					writeError(w, http.StatusInternalServerError, "internal error")
					return
				}
				writeError(w, http.StatusUnauthorized, "session not found")
				return
			}
			if err != nil {
				writeError(w, http.StatusInternalServerError, "internal error")
				return
			}

			if userDisabled.Valid {
				if _, err := auth.WriteAuditEvent(r.Context(), db, auth.AuditEventInput{
					EventType: "auth.access_denied",
					UserID:    claims.UserID,
					SessionID: claims.SessionID,
					Metadata:  map[string]any{"reason": "user disabled"},
				}); err != nil {
					writeError(w, http.StatusInternalServerError, "internal error")
					return
				}
				writeError(w, http.StatusUnauthorized, "invalid email or password")
				return
			}

			if sessionRevoked.Valid {
				if _, err := auth.WriteAuditEvent(r.Context(), db, auth.AuditEventInput{
					EventType: "auth.access_denied",
					UserID:    claims.UserID,
					SessionID: claims.SessionID,
					Metadata:  map[string]any{"reason": "session revoked"},
				}); err != nil {
					writeError(w, http.StatusInternalServerError, "internal error")
					return
				}
				writeError(w, http.StatusUnauthorized, "session has been revoked")
				return
			}

			if sessionExpires.Before(time.Now()) {
				if _, err := auth.WriteAuditEvent(r.Context(), db, auth.AuditEventInput{
					EventType: "auth.access_denied",
					UserID:    claims.UserID,
					SessionID: claims.SessionID,
					Metadata:  map[string]any{"reason": "session expired"},
				}); err != nil {
					writeError(w, http.StatusInternalServerError, "internal error")
					return
				}
				writeError(w, http.StatusUnauthorized, "session has expired")
				return
			}

			roles, err := auth.LoadUserRoles(r.Context(), db, claims.UserID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "internal error")
				return
			}
			if roles == nil {
				roles = []string{}
			}

			ctx := SetUser(r.Context(), UserInfo{
				UserID:    claims.UserID,
				Name:      name,
				Email:     email,
				SessionID: claims.SessionID,
				Roles:     roles,
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

func RequireRole(db *sql.DB, requiredRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := GetUser(r.Context())
			if !ok {
				writeError(w, http.StatusUnauthorized, "not authenticated")
				return
			}

			for _, role := range user.Roles {
				if role == requiredRole {
					next.ServeHTTP(w, r)
					return
				}
			}

			if _, err := auth.WriteAuditEvent(r.Context(), db, auth.AuditEventInput{
				EventType: "auth.access_denied",
				UserID:    user.UserID,
				SessionID: user.SessionID,
				Metadata: map[string]any{
					"reason":     "insufficient role",
					"required":   requiredRole,
					"user_roles": user.Roles,
				},
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "internal error")
				return
			}

			writeError(w, http.StatusForbidden, "access denied")
		})
	}
}
