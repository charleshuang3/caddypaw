package caddypaw

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckBearerToken(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		token          string
		expectedStatus int
		expectError    bool
	}{
		{
			name:           "valid token",
			authHeader:     "Bearer test-token",
			token:          "test-token",
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "missing authorization header",
			authHeader:     "",
			token:          "test-token",
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
		},
		{
			name:           "invalid authorization header format",
			authHeader:     "test-token",
			token:          "test-token",
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
		},
		{
			name:           "invalid token",
			authHeader:     "Bearer wrong-token",
			token:          "test-token",
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authModule{
				Token: tt.token,
			}

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Authorization", tt.authHeader)

			status, _, err := a.checkBearerToken(w, r)

			assert.Equal(t, tt.expectedStatus, status)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
