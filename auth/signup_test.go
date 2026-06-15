package auth

import (
	"testing"
)

func TestValidateSignup(t *testing.T) {
	tests := []struct {
		name    string
		input   SignInSignUpParameters
		wantErr bool
		want    SignInSignUpParameters
	}{
		{
			name: "valid input",
			input: SignInSignUpParameters{
				Name:     " Alice ",
				Email:    " Alice@Example.com ",
				Password: "password123",
			},
			wantErr: false,
			want: SignInSignUpParameters{
				Name:     "Alice",
				Email:    "alice@example.com",
				Password: "password123",
			},
		},
		{
			name: "empty name",
			input: SignInSignUpParameters{
				Name:     "   ",
				Email:    "alice@example.com",
				Password: "password123",
			},
			wantErr: true,
		},
		{
			name: "empty email",
			input: SignInSignUpParameters{
				Name:     "Alice",
				Email:    "",
				Password: "password123",
			},
			wantErr: true,
		},
		{
			name: "whitespace-only email",
			input: SignInSignUpParameters{
				Name:     "Alice",
				Email:    "   ",
				Password: "password123",
			},
			wantErr: true,
		},
		{
			name: "whitespace-only password",
			input: SignInSignUpParameters{
				Name:     "Alice",
				Email:    "alice@example.com",
				Password: "   ",
			},
			wantErr: true,
		},
		{
			name: "password 7 chars fails",
			input: SignInSignUpParameters{
				Name:     "Alice",
				Email:    "alice@example.com",
				Password: "1234567",
			},
			wantErr: true,
		},
		{
			name: "password 8 chars passes",
			input: SignInSignUpParameters{
				Name:     "Alice",
				Email:    "alice@example.com",
				Password: "12345678",
			},
			wantErr: false,
			want: SignInSignUpParameters{
				Name:     "Alice",
				Email:    "alice@example.com",
				Password: "12345678",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateSignup(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got.Name != tt.want.Name {
				t.Errorf("name = %q, want %q", got.Name, tt.want.Name)
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
