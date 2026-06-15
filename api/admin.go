package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

type adminUserResponse struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Disabled bool     `json:"disabled"`
	Roles    []string `json:"roles"`
}

func AdminUsersHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.QueryContext(r.Context(),
			`SELECT u.id, u.name, u.email, u.disabled_at, r.name
			 FROM users u
			 LEFT JOIN user_roles ur ON ur.user_id = u.id
			 LEFT JOIN roles r ON r.id = ur.role_id
			 ORDER BY u.created_at`,
		)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		defer rows.Close()

		users := make(map[string]*adminUserResponse)
		var order []string

		for rows.Next() {
			var id, name, email, roleName sql.NullString
			var disabledAt sql.NullTime

			if err := rows.Scan(&id, &name, &email, &disabledAt, &roleName); err != nil {
				writeError(w, http.StatusInternalServerError, "internal error")
				return
			}

			uid := id.String
			if _, exists := users[uid]; !exists {
				users[uid] = &adminUserResponse{
					ID:       uid,
					Name:     name.String,
					Email:    email.String,
					Disabled: disabledAt.Valid,
					Roles:    []string{},
				}
				order = append(order, uid)
			}

			if roleName.Valid {
				users[uid].Roles = append(users[uid].Roles, roleName.String)
			}
		}

		if err := rows.Err(); err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		result := make([]adminUserResponse, 0, len(order))
		for _, uid := range order {
			u := users[uid]
			if u.Roles == nil {
				u.Roles = []string{}
			}
			result = append(result, *u)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}
