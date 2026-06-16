package api

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/veerbal1/go-auth-sessions-jwt/auth"
)

type logoutResponse struct {
	Message string `json:"message"`
}

func LogoutHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := GetUser(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "not authenticated")
			return
		}

		if err := auth.RevokeSession(r.Context(), db, user.SessionID); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to revoke session")
			return
		}

		if _, err := auth.WriteAuditEvent(r.Context(), db, auth.AuditEventInput{
			EventType: "auth.logout",
			UserID:    user.UserID,
			SessionID: user.SessionID,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "access_token",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   -1,
		})

		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    "",
			Path:     "/api/v1/refresh",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   -1,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(logoutResponse{Message: "logged out"})
	}
}
