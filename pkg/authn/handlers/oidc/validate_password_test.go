package oidc

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		expectedErr error
	}{
		{
			name:        "valid password",
			password:    "ValidP@ss1",
			expectedErr: nil,
		},
		{
			name:        "valid password with all allowed special chars",
			password:    "Val!@#$%^&*()_+-=[]{};':\"\\|,.<>/?1dP@ss",
			expectedErr: nil,
		},
		{
			name:        "too short",
			password:    "V@lid1",
			expectedErr: errors.New("password must be at least 8 characters long"),
		},
		{
			name:        "missing number",
			password:    "ValidP@ssword",
			expectedErr: errors.New("password must contain at least one number"),
		},
		{
			name:        "missing lowercase",
			password:    "VALIDP@SS1",
			expectedErr: errors.New("password must contain at least one lowercase letter"),
		},
		{
			name:        "missing uppercase",
			password:    "validp@ss1",
			expectedErr: errors.New("password must contain at least one uppercase letter"),
		},
		{
			name:        "missing special char",
			password:    "ValidPass1",
			expectedErr: errors.New("password must contain at least one special character"),
		},
		{
			name:        "disallowed character (space)",
			password:    "ValidP@ss 1",
			expectedErr: errors.New("password contains disallowed characters"),
		},
		{
			name:        "disallowed character (tab)",
			password:    "ValidP@ss\t1",
			expectedErr: errors.New("password contains disallowed characters"),
		},
		{
			name:        "disallowed character (emoji)",
			password:    "ValidP@ss😊1",
			expectedErr: errors.New("password contains disallowed characters"),
		},
		{
			name:        "empty password",
			password:    "",
			expectedErr: errors.New("password must be at least 8 characters long"),
		},
		{
			name:        "only numbers",
			password:    "12345678",
			expectedErr: errors.New("password must contain at least one lowercase letter"),
		},
		{
			name:        "only lowercase",
			password:    "abcdefgh",
			expectedErr: errors.New("password must contain at least one number"),
		},
		{
			name:        "only uppercase",
			password:    "ABCDEFGH",
			expectedErr: errors.New("password must contain at least one number"),
		},
		{
			name:        "only special chars",
			password:    "!!!!!!!!",
			expectedErr: errors.New("password must contain at least one number"),
		},
		{
			name:        "no special but meets other criteria",
			password:    "ValidPassword1",
			expectedErr: errors.New("password must contain at least one special character"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePassword(tt.password)
			if tt.expectedErr == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.expectedErr.Error())
			}
		})
	}
}
