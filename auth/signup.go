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
		return SignInSignUpParameters{}, fmt.Errorf("name must not be empty")
	}

	email := strings.TrimSpace(in.Email)
	if email == "" {
		return SignInSignUpParameters{}, fmt.Errorf("email must not be empty")
	}
	email = strings.ToLower(email)

	if strings.TrimSpace(in.Password) == "" {
		return SignInSignUpParameters{}, fmt.Errorf("password must not be empty")
	}
	if len(in.Password) < 8 {
		return SignInSignUpParameters{}, fmt.Errorf("password must be at least 8 characters")
	}

	return SignInSignUpParameters{
		Name:     name,
		Email:    email,
		Password: in.Password,
	}, nil
}
