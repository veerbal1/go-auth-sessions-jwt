package auth

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"
)

type CreatedUser struct {
	ID    string
	Name  string
	Email string
}

func Signup(ctx context.Context, db *sql.DB, in SignInSignUpParameters) (CreatedUser, error) {
	prepared, err := PrepareSignup(in)
	if err != nil {
		return CreatedUser{}, err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return CreatedUser{}, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var userID string
	err = tx.QueryRowContext(ctx,
		`INSERT INTO users (name, email, hashed_password) VALUES ($1, $2, $3) RETURNING id`,
		prepared.Name, prepared.Email, prepared.HashedPassword,
	).Scan(&userID)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return CreatedUser{}, NewConflictError("email already registered")
		}
		return CreatedUser{}, fmt.Errorf("failed to insert user: %w", err)
	}

	var roleID string
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM roles WHERE name = 'user'`,
	).Scan(&roleID)
	if err != nil {
		return CreatedUser{}, fmt.Errorf("failed to find user role: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`,
		userID, roleID,
	)
	if err != nil {
		return CreatedUser{}, fmt.Errorf("failed to assign role: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return CreatedUser{}, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return CreatedUser{
		ID:    userID,
		Name:  prepared.Name,
		Email: prepared.Email,
	}, nil
}

func Login(ctx context.Context, db *sql.DB, in LoginInput) (CreatedUser, error) {
	validated, err := ValidateLogin(in)
	if err != nil {
		return CreatedUser{}, err
	}

	var user CreatedUser
	var hashedPassword string
	var disabledAt sql.NullTime

	err = db.QueryRowContext(ctx,
		`SELECT id, name, email, hashed_password, disabled_at FROM users WHERE email = $1`,
		validated.Email,
	).Scan(&user.ID, &user.Name, &user.Email, &hashedPassword, &disabledAt)
	if err == sql.ErrNoRows {
		return CreatedUser{}, NewAuthenticationError("invalid email or password")
	}
	if err != nil {
		return CreatedUser{}, fmt.Errorf("failed to find user: %w", err)
	}

	if disabledAt.Valid {
		return CreatedUser{}, NewAuthenticationError("invalid email or password")
	}

	if !VerifyPassword(hashedPassword, validated.Password) {
		return CreatedUser{}, NewAuthenticationError("invalid email or password")
	}

	return user, nil
}
