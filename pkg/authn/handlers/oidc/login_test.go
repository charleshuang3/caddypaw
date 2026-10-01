package oidc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/charleshuang3/caddypaw/pkg/authn/gormw"
	"github.com/charleshuang3/caddypaw/pkg/authn/models"
	"github.com/charleshuang3/caddypaw/pkg/authn/storage"
)

func setupTestProviderForLogin(t *testing.T) (*OpenIDProvider, *gormw.DB, *gin.Engine) {
	t.Helper()

	provider, db, router := setupTestProvider(t)

	// Pre-create a user for tests
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)
	require.NoError(t, err)
	existingUser := models.User{
		Username:       "existinguser",
		Email:          "existing@example.com",
		HashedPassword: string(hashedPassword),
	}
	err = db.Create(&existingUser).Error
	require.NoError(t, err)

	// A state that will be pre-added to storage for some tests
	validStateKey := "valid-state-for-login"
	validAuthState := &storage.AuthState{
		ClientID:    "test-client",
		RedirectURI: "http://localhost/callback",
		Scopes:      []string{"openid"},
	}
	provider.authStateStorage.Set(validStateKey, validAuthState)

	return provider, db, router
}

func TestHandleLogin_SuccessfulLogin(t *testing.T) {
	provider, _, router := setupTestProviderForLogin(t)

	formData := url.Values{
		"username": {"existinguser"},
		"password": {"correctpassword"},
		"state":    {"valid-state-for-login"},
	}
	req, err := http.NewRequest(http.MethodPost, "/user/login", strings.NewReader(formData.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Check for redirect status
	assert.Equal(t, http.StatusFound, rec.Code, fmt.Sprintf("Expected status %d, got %d. Body: %s", http.StatusFound, rec.Code, rec.Body.String()))

	// Check redirect location
	locationHeader := rec.Header().Get("Location")
	assert.NotEmpty(t, locationHeader, "Expected Location header to be set")
	assert.True(t, strings.HasPrefix(locationHeader, "http://localhost/callback?"), "Expected redirect to callback with query parameters")

	// Parse redirect URL to extract code and state
	parsedURL, err := url.Parse(locationHeader)
	require.NoError(t, err, "Expected valid URL in Location header")
	query := parsedURL.Query()
	codeParam := query.Get("code")
	stateParam := query.Get("state")
	assert.NotEmpty(t, codeParam, "Expected code parameter in redirect URL")
	assert.Equal(t, "valid-state-for-login", stateParam, "Expected state parameter to match the input state")

	// Verify the code is stored
	code, ok := provider.authCodeStorage.Get(codeParam)
	assert.True(t, ok, "Expected authorization code to be stored")
	assert.Equal(t, "test-client", code.ClientID, "Expected client ID to match")
	assert.Equal(t, "http://localhost/callback", code.RedirectURI, "Expected redirect URI to match")
	assert.Contains(t, code.Scopes, "openid", "Expected scopes to include openid")

	// Verify state was removed after use
	_, ok = provider.authStateStorage.Get("valid-state-for-login")
	assert.False(t, ok, "Expected state to be removed after use")
}

func TestHandleLogin_ErrorCases(t *testing.T) {
	tests := []struct {
		name           string
		formData       url.Values
		setupState     func(p *OpenIDProvider) // Optional: for specific state setups per test
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "Missing username",
			formData: url.Values{
				"password": {"testpassword"},
				"state":    {"some-state"},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing required parameters",
		},
		{
			name: "Missing password",
			formData: url.Values{
				"username": {"testuser"},
				"state":    {"some-state"},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing required parameters",
		},
		{
			name: "Missing state",
			formData: url.Values{
				"username": {"testuser"},
				"password": {"testpassword"},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing required parameters",
		},
		{
			name: "Invalid or expired state",
			formData: url.Values{
				"username": {"testuser"},
				"password": {"testpassword"},
				"state":    {"invalid-state-key"},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid state",
		},
		{
			name: "User not found",
			formData: url.Values{
				"username": {"nonexistentuser"},
				"password": {"testpassword"},
				"state":    {"valid-state-for-login"},
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid username or password",
		},
		{
			name: "Username with incorrect password",
			formData: url.Values{
				"username": {"existinguser"},
				"password": {"wrongpassword"},
				"state":    {"valid-state-for-login"},
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid username or password",
		},
		{
			name: "Email with incorrect password",
			formData: url.Values{
				"username": {"existing@example.com"},
				"password": {"wrongpassword"},
				"state":    {"valid-state-for-login"},
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid username or password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, router := setupTestProviderForLogin(t)

			req, err := http.NewRequest(http.MethodPost, "/user/login", strings.NewReader(tt.formData.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code, fmt.Sprintf("Expected status %d, got %d. Body: %s", tt.expectedStatus, rec.Code, rec.Body.String()))
			assert.Contains(t, rec.Body.String(), tt.expectedBody)
		})
	}
}
