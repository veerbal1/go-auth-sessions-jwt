package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"auth-lab/auth"
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

func LoginHandler(db *sql.DB, jwtSecret []byte) http.HandlerFunc {
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
				writeError(w, http.StatusUnauthorized, err.Error())
			default:
				writeError(w, http.StatusInternalServerError, "internal error")
			}
			return
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
