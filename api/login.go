package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/veerbal1/go-auth-sessions-jwt/auth"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	UserID           string    `json:"user_id"`
	Name             string    `json:"name"`
	Email            string    `json:"email"`
	SessionID        string    `json:"session_id"`
	SessionExpiresAt time.Time `json:"session_expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

func LoginHandler(db *sql.DB, jwtSecret []byte, rdb *redis.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var req loginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		clientIP := extractClientIP(r)

		if rdb != nil {
			if err := auth.CheckRateLimit(r.Context(), rdb, req.Email, clientIP); err != nil {
				var rateErr *auth.RateLimitError
				if errors.As(err, &rateErr) {
					writeError(w, http.StatusTooManyRequests, err.Error())
					return
				}
				writeError(w, http.StatusInternalServerError, "internal error")
				return
			}
		}

		result, err := auth.LoginWithRefreshToken(
			r.Context(), db,
			auth.LoginInput{Email: req.Email, Password: req.Password},
			jwtSecret,
			15*time.Minute, // session lifetime
			7*24*time.Hour, // refresh lifetime
			15*time.Minute, // access token lifetime
			r.UserAgent(),
			"", // ip_hash, leave empty for now
		)
		if err != nil {
			var valErr *auth.ValidationError
			var authErr *auth.AuthenticationError
			switch {
			case errors.As(err, &valErr):
				writeError(w, http.StatusBadRequest, err.Error())
			case errors.As(err, &authErr):
				if rdb != nil {
					if recErr := auth.RecordLoginFailure(r.Context(), rdb, req.Email, clientIP); recErr != nil {
						writeError(w, http.StatusInternalServerError, "internal error")
						return
					}
				}
				writeError(w, http.StatusUnauthorized, err.Error())
			default:
				writeError(w, http.StatusInternalServerError, "internal error")
			}
			return
		}

		if rdb != nil {
			if recErr := auth.RecordLoginSuccess(r.Context(), rdb, req.Email, clientIP); recErr != nil {
				writeError(w, http.StatusInternalServerError, "internal error")
				return
			}
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "access_token",
			Value:    result.AccessToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   15 * 60,
		})

		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    result.RefreshToken,
			Path:     "/api/v1/refresh",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   7 * 24 * 60 * 60,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(loginResponse{
			UserID:           result.UserID,
			Name:             result.Name,
			Email:            result.Email,
			SessionID:        result.SessionID,
			SessionExpiresAt: result.SessionExpiresAt,
			RefreshExpiresAt: result.RefreshExpiresAt,
		})
	}
}

func extractClientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		return strings.TrimSpace(parts[0])
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
