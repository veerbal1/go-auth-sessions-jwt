package auth

import "strings"

type LoginInput struct {
	Email    string
	Password string
}

type LoginOutput struct {
	Email    string
	Password string
}

func ValidateLogin(in LoginInput) (LoginOutput, error) {
	email := strings.TrimSpace(in.Email)
	if email == "" {
		return LoginOutput{}, NewValidationError("email must not be empty")
	}
	email = strings.ToLower(email)

	if strings.TrimSpace(in.Password) == "" {
		return LoginOutput{}, NewValidationError("password must not be empty")
	}

	return LoginOutput{
		Email:    email,
		Password: in.Password,
	}, nil
}
