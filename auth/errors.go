package auth

import "fmt"

type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

func NewValidationError(msg string) error {
	return &ValidationError{Message: msg}
}

func NewValidationErrorf(format string, args ...interface{}) error {
	return &ValidationError{Message: fmt.Sprintf(format, args...)}
}

type ConflictError struct {
	Message string
}

func (e *ConflictError) Error() string {
	return e.Message
}

func NewConflictError(msg string) error {
	return &ConflictError{Message: msg}
}

type AuthenticationError struct {
	Message string
}

func (e *AuthenticationError) Error() string {
	return e.Message
}

func NewAuthenticationError(msg string) error {
	return &AuthenticationError{Message: msg}
}
