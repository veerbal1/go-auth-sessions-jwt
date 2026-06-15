package auth

import (
	"context"
	"encoding/json"
	"fmt"
)

type AuditEventInput struct {
	EventType string
	UserID    string
	SessionID string
	RequestID string
	IPHash    string
	UserAgent string
	Metadata  interface{}
}

func WriteAuditEvent(ctx context.Context, db Querier, in AuditEventInput) (string, error) {
	var metadataJSON []byte
	if in.Metadata != nil {
		var err error
		metadataJSON, err = json.Marshal(in.Metadata)
		if err != nil {
			return "", fmt.Errorf("failed to marshal metadata: %w", err)
		}
	}

	nullableString := func(s string) interface{} {
		if s == "" {
			return nil
		}
		return s
	}

	var id string
	err := db.QueryRowContext(ctx,
		`INSERT INTO audit_events (event_type, user_id, session_id, request_id, ip_hash, user_agent, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		in.EventType,
		nullableString(in.UserID),
		nullableString(in.SessionID),
		nullableString(in.RequestID),
		nullableString(in.IPHash),
		nullableString(in.UserAgent),
		metadataJSON,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("failed to insert audit event: %w", err)
	}

	return id, nil
}
