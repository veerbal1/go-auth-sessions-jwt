package auth

import (
	"errors"
	"testing"
)

func TestValidateLogin(t *testing.T) {
	tests := []struct {
		name    string
		input   LoginInput
		wantErr bool
		want    LoginOutput
	}{
		{
			name: "valid input",
			input: LoginInput{
				Email:    " Alice@Example.com ",
				Password: "password123",
			},
			wantErr: false,
			want: LoginOutput{
				Email:    "alice@example.com",
				Password: "password123",
			},
		},
		{
			name: "empty email",
			input: LoginInput{
				Email:    "",
				Password: "password123",
			},
			wantErr: true,
		},
		{
			name: "whitespace-only email",
			input: LoginInput{
				Email:    "   ",
				Password: "password123",
			},
			wantErr: true,
		},
		{
			name: "empty password",
			input: LoginInput{
				Email:    "alice@example.com",
				Password: "",
			},
			wantErr: true,
		},
		{
			name: "whitespace-only password",
			input: LoginInput{
				Email:    "alice@example.com",
				Password: "   ",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateLogin(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				var valErr *ValidationError
				if !errors.As(err, &valErr) {
					t.Errorf("expected ValidationError, got %T", err)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got.Email != tt.want.Email {
				t.Errorf("email = %q, want %q", got.Email, tt.want.Email)
			}
			if got.Password != tt.want.Password {
				t.Errorf("password = %q, want %q", got.Password, tt.want.Password)
			}
		})
	}
}
