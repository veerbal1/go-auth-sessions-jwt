package auth

import (
	"fmt"
	"strings"
)

type SignInSignUpParameters struct {
	Name     string
	Email    string
	Password string
}

func ValidateSignup(in SignInSignUpParameters) (SignInSignUpParameters, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return SignInSignUpParameters{}, NewValidationError("name must not be empty")
	}

	email := strings.TrimSpace(in.Email)
	if email == "" {
		return SignInSignUpParameters{}, NewValidationError("email must not be empty")
	}
	email = strings.ToLower(email)

	if strings.TrimSpace(in.Password) == "" {
		return SignInSignUpParameters{}, NewValidationError("password must not be empty")
	}
	if len(in.Password) < 8 {
		return SignInSignUpParameters{}, NewValidationError("password must be at least 8 characters")
	}

	return SignInSignUpParameters{
		Name:     name,
		Email:    email,
		Password: in.Password,
	}, nil
}

type PreparedSignup struct {
	Name           string
	Email          string
	HashedPassword string
}

func PrepareSignup(in SignInSignUpParameters) (PreparedSignup, error) {
	validated, err := ValidateSignup(in)
	if err != nil {
		return PreparedSignup{}, err
	}

	hash, err := HashPassword(validated.Password)
	if err != nil {
		return PreparedSignup{}, fmt.Errorf("failed to hash password: %w", err)
	}

	return PreparedSignup{
		Name:           validated.Name,
		Email:          validated.Email,
		HashedPassword: hash,
	}, nil
}
