package auth

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

func TestQueueNewLoginAlert(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	user, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Outbox Test",
		Email:    email,
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	jobID, err := QueueNewLoginAlert(context.Background(), db, user.ID, email)
	if err != nil {
		t.Fatalf("QueueNewLoginAlert failed: %v", err)
	}
	if jobID == "" {
		t.Error("job ID must not be empty")
	}

	var dbUserID, dbRecipientEmail, dbSubject, dbBody, dbStatus string
	var dbAttemptCount int
	var dbLastError sql.NullString

	err = db.QueryRowContext(context.Background(),
		`SELECT user_id, recipient_email, subject, body, status, attempt_count, last_error
		 FROM email_outbox WHERE id = $1`, jobID,
	).Scan(&dbUserID, &dbRecipientEmail, &dbSubject, &dbBody, &dbStatus, &dbAttemptCount, &dbLastError)
	if err != nil {
		t.Fatalf("failed to read email outbox: %v", err)
	}

	if dbUserID != user.ID {
		t.Errorf("user_id = %q, want %q", dbUserID, user.ID)
	}
	if dbRecipientEmail != email {
		t.Errorf("recipient_email = %q, want %q", dbRecipientEmail, email)
	}
	if dbStatus != "pending" {
		t.Errorf("status = %q, want %q", dbStatus, "pending")
	}
	if dbAttemptCount != 0 {
		t.Errorf("attempt_count = %d, want 0", dbAttemptCount)
	}
	if dbLastError.Valid {
		t.Error("last_error must be null on creation")
	}

	if !strings.Contains(dbBody, "new login") && !strings.Contains(dbBody, "change your password") {
		t.Error("body must contain the security warning")
	}

	forbidden := []string{"password123", "password hash", "refresh token", "reset token", "hashed_password"}
	for _, word := range forbidden {
		if strings.Contains(strings.ToLower(dbBody), word) {
			t.Errorf("body must not contain %q", word)
		}
	}
}
