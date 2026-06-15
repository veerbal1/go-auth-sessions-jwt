package api

import (
	"encoding/json"
	"net/http"
)

type meResponse struct {
	UserID    string   `json:"user_id"`
	Name      string   `json:"name"`
	Email     string   `json:"email"`
	SessionID string   `json:"session_id"`
	Roles     []string `json:"roles"`
}

func MeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := GetUser(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "not authenticated")
			return
		}

		roles := user.Roles
		if roles == nil {
			roles = []string{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meResponse{
			UserID:    user.UserID,
			Name:      user.Name,
			Email:     user.Email,
			SessionID: user.SessionID,
			Roles:     roles,
		})
	}
}
