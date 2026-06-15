package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"
)

func TestWriteAuditEvent(t *testing.T) {
	db := testDB(t)

	email := uniqueEmail()
	password := "password123"

	user, err := Signup(context.Background(), db, SignInSignUpParameters{
		Name:     "Audit Test",
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	defer func() {
		db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.ID)
	}()

	session, err := CreateSession(context.Background(), db, user.ID, 15*time.Minute, "", "")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	eventID, err := WriteAuditEvent(context.Background(), db, AuditEventInput{
		EventType: "auth.login_success",
		UserID:    user.ID,
		SessionID: session.ID,
		Metadata: map[string]interface{}{
			"ip":    "127.0.0.1",
			"agent": "test/1.0",
		},
	})
	if err != nil {
		t.Fatalf("WriteAuditEvent failed: %v", err)
	}
	if eventID == "" {
		t.Error("event ID must not be empty")
	}

	var dbEventType, dbUserID, dbSessionID string
	var dbMetadata []byte
	var dbCreatedAt time.Time

	err = db.QueryRowContext(context.Background(),
		`SELECT event_type, user_id, session_id, metadata, created_at
		 FROM audit_events WHERE id = $1`, eventID,
	).Scan(&dbEventType, &dbUserID, &dbSessionID, &dbMetadata, &dbCreatedAt)
	if err != nil {
		t.Fatalf("failed to read audit event: %v", err)
	}

	if dbEventType != "auth.login_success" {
		t.Errorf("event_type = %q, want %q", dbEventType, "auth.login_success")
	}
	if dbUserID != user.ID {
		t.Errorf("user_id = %q, want %q", dbUserID, user.ID)
	}
	if dbSessionID != session.ID {
		t.Errorf("session_id = %q, want %q", dbSessionID, session.ID)
	}
	if dbCreatedAt.IsZero() {
		t.Error("created_at must be set")
	}

	var metadata map[string]interface{}
	if err := json.Unmarshal(dbMetadata, &metadata); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}
	if metadata["ip"] != "127.0.0.1" {
		t.Errorf("metadata ip = %v, want 127.0.0.1", metadata["ip"])
	}
	if metadata["agent"] != "test/1.0" {
		t.Errorf("metadata agent = %v, want test/1.0", metadata["agent"])
	}
}

func TestWriteAuditEventMinimal(t *testing.T) {
	db := testDB(t)

	eventID, err := WriteAuditEvent(context.Background(), db, AuditEventInput{
		EventType: "auth.login_failed",
	})
	if err != nil {
		t.Fatalf("WriteAuditEvent failed: %v", err)
	}

	var dbUserID, dbSessionID sql.NullString

	db.QueryRowContext(context.Background(),
		`SELECT user_id, session_id FROM audit_events WHERE id = $1`, eventID,
	).Scan(&dbUserID, &dbSessionID)

	if dbUserID.Valid {
		t.Error("user_id must be null when not provided")
	}
	if dbSessionID.Valid {
		t.Error("session_id must be null when not provided")
	}
}
