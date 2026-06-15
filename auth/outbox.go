package auth

import (
	"context"
	"fmt"
)

func QueueNewLoginAlert(ctx context.Context, db Querier, userID, recipientEmail string) (string, error) {
	subject := "New login to your account"
	body := "A new login session was created. If this was not you, change your password."

	var id string
	err := db.QueryRowContext(ctx,
		`INSERT INTO email_outbox (user_id, recipient_email, subject, body)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		userID, recipientEmail, subject, body,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("failed to queue email: %w", err)
	}

	return id, nil
}
