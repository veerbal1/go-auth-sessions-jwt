package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/veerbal1/go-auth-sessions-jwt/auth"
)

type refreshResponse struct {
	Message          string    `json:"message"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

func RefreshHandler(db *sql.DB, jwtSecret []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		cookie, err := r.Cookie("refresh_token")
		if err != nil {
			writeError(w, http.StatusUnauthorized, "missing refresh token")
			return
		}

		rotated, err := auth.RotateRefreshToken(
			r.Context(), db,
			cookie.Value, jwtSecret,
			15*time.Minute, // access token lifetime
			7*24*time.Hour, // refresh token lifetime
		)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "access_token",
			Value:    rotated.AccessToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   15 * 60,
		})

		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    rotated.RefreshToken,
			Path:     "/api/v1/refresh",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   7 * 24 * 60 * 60,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(refreshResponse{
			Message:          "token refreshed",
			RefreshExpiresAt: rotated.RefreshExpiresAt,
		})
	}
}
