package oidc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/charleshuang3/caddypaw/pkg/authn/gormw"
	"github.com/charleshuang3/caddypaw/pkg/authn/models"
	"github.com/charleshuang3/caddypaw/pkg/authn/storage"
)

func TestRegisterPage(t *testing.T) {
	testCases := []struct {
		name         string
		state        string
		expectedCode int
		expectedBody string
		setup        func(p *OpenIDProvider)
	}{
		{
			name:         "Success",
			state:        "test-state",
			expectedCode: http.StatusOK,
			expectedBody: "Register",
			setup: func(p *OpenIDProvider) {
				p.authStateStorage.Set("test-state", &storage.AuthState{
					ClientID:    "test-client",
					RedirectURI: "http://localhost/callback",
					Scopes:      []string{"openid"},
				})
			},
		},
		{
			name:         "Invalid state",
			state:        "test-state",
			expectedCode: http.StatusBadRequest,
			expectedBody: "Invalid or expired state",
			setup:        func(p *OpenIDProvider) {}, // do not add state
		},
		{
			name:         "Missing state",
			state:        "",
			expectedCode: http.StatusBadRequest,
			expectedBody: "Missing state parameter",
			setup:        func(p *OpenIDProvider) {},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p, _, router := setupTestProvider(t)
			if tc.setup != nil {
				tc.setup(p)
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/user/register?state="+tc.state, nil)

			router.ServeHTTP(rec, req)

			assert.Equal(t, tc.expectedCode, rec.Code)
			assert.Contains(t, rec.Body.String(), tc.expectedBody)
		})
	}
}

func TestHandleUserRegister_Success(t *testing.T) {
	p, db, router := setupTestProvider(t)

	// Setup auth state
	state := "test-state-success"
	p.authStateStorage.Set(state, &storage.AuthState{
		ClientID:    "test-client",
		RedirectURI: "http://localhost/callback",
		Scopes:      []string{"openid"},
	})

	// Setup invitation code
	invitationCode := "valid-invitation-code"
	require.NoError(t, storage.AddInvitation(db, invitationCode, "user-role"))

	// Form data for successful registration
	formData := url.Values{
		"username":        {"newuser"},
		"email":           {"newuser@example.com"},
		"password":        {"Password123!"},
		"invitation_code": {invitationCode},
		"state":           {state},
	}

	req, err := http.NewRequest(http.MethodPost, "/user/register", strings.NewReader(formData.Encode()))
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
	assert.Equal(t, state, stateParam, "Expected state parameter to match the input state")

	// Verify the code is stored
	code, ok := p.authCodeStorage.Get(codeParam)
	assert.True(t, ok, "Expected authorization code to be stored")
	assert.Equal(t, "test-client", code.ClientID, "Expected client ID to match")
	assert.Equal(t, "http://localhost/callback", code.RedirectURI, "Expected redirect URI to match")
	assert.Contains(t, code.Scopes, "openid", "Expected scopes to include openid")

	// Verify state was removed after use
	_, ok = p.authStateStorage.Get(state)
	assert.False(t, ok, "Expected state to be removed after use")

	// Verify user was created in the database
	user, err := storage.GetUserByUsernameOrEmail(db, "newuser")
	assert.NoError(t, err, "Expected user to be created in database")
	assert.Equal(t, "newuser", user.Username, "Expected username to match")
	assert.Equal(t, "newuser@example.com", user.Email, "Expected email to match")

	// Verify invitation use count was updated
	invitation, err := storage.GetInvitationByCode(db, invitationCode)
	assert.NoError(t, err, "Expected invitation to be found")
	assert.Equal(t, uint(1), invitation.UseCount, "Expected invitation use count to be incremented")
}

func TestHandleUserRegister_Error(t *testing.T) {
	testCases := []struct {
		name         string
		formData     url.Values
		expectedCode int
		expectedBody string
		setup        func(p *OpenIDProvider, db *gormw.DB)
	}{
		{
			name: "Missing username",
			formData: url.Values{
				"email":           {"test@example.com"},
				"password":        {"Password123!"},
				"invitation_code": {"test-code"},
				"state":           {"test-state"},
			},
			expectedCode: http.StatusBadRequest,
			expectedBody: "Missing required parameters",
		},
		{
			name: "Missing email",
			formData: url.Values{
				"username":        {"testuser"},
				"password":        {"Password123!"},
				"invitation_code": {"test-code"},
				"state":           {"test-state"},
			},
			expectedCode: http.StatusBadRequest,
			expectedBody: "Missing required parameters",
		},
		{
			name: "Missing password",
			formData: url.Values{
				"username":        {"testuser"},
				"email":           {"test@example.com"},
				"invitation_code": {"test-code"},
				"state":           {"test-state"},
			},
			expectedCode: http.StatusBadRequest,
			expectedBody: "Missing required parameters",
		},
		{
			name: "Missing invitation_code",
			formData: url.Values{
				"username": {"testuser"},
				"email":    {"test@example.com"},
				"password": {"Password123!"},
				"state":    {"test-state"},
			},
			expectedCode: http.StatusBadRequest,
			expectedBody: "Missing required parameters",
		},
		{
			name: "Missing state",
			formData: url.Values{
				"username":        {"testuser"},
				"email":           {"test@example.com"},
				"password":        {"Password123!"},
				"invitation_code": {"test-code"},
			},
			expectedCode: http.StatusBadRequest,
			expectedBody: "Missing required parameters",
		},
		{
			name: "Invalid username format",
			formData: url.Values{
				"username":        {"invalid username"},
				"email":           {"test@example.com"},
				"password":        {"Password123!"},
				"invitation_code": {"test-code"},
				"state":           {"test-state"},
			},
			expectedCode: http.StatusBadRequest,
			expectedBody: "Invalid username format",
		},
		{
			name: "Invalid email format",
			formData: url.Values{
				"username":        {"testuser"},
				"email":           {"invalid-email"},
				"password":        {"Password123!"},
				"invitation_code": {"test-code"},
				"state":           {"test-state"},
			},
			expectedCode: http.StatusBadRequest,
			expectedBody: "Invalid email format",
		},
		{
			name: "Invalid password format",
			formData: url.Values{
				"username":        {"testuser"},
				"email":           {"test@example.com"},
				"password":        {"invalid"},
				"invitation_code": {"test-code"},
				"state":           {"test-state"},
			},
			expectedCode: http.StatusBadRequest,
			expectedBody: "password must be at least 8 characters long",
		},
		{
			name: "Empty invitation code",
			formData: url.Values{
				"username":        {"testuser"},
				"email":           {"test@example.com"},
				"password":        {"Password123!"},
				"invitation_code": {"   "},
				"state":           {"test-state"},
			},
			expectedCode: http.StatusBadRequest,
			expectedBody: "Invitation code cannot be empty.",
		},
		{
			name: "Invalid state",
			formData: url.Values{
				"username":        {"testuser"},
				"email":           {"test@example.com"},
				"password":        {"Password123!"},
				"invitation_code": {"test-code"},
				"state":           {"invalid-state"},
			},
			expectedCode: http.StatusBadRequest,
			expectedBody: "Invalid or expired state.",
		},
		{
			name: "Invalid invitation code",
			formData: url.Values{
				"username":        {"testuser"},
				"email":           {"test@example.com"},
				"password":        {"Password123!"},
				"invitation_code": {"invalid-code"},
				"state":           {"test-state"},
			},
			expectedCode: http.StatusBadRequest,
			expectedBody: "Invalid invitation code.",
			setup: func(p *OpenIDProvider, db *gormw.DB) {
				p.authStateStorage.Set("test-state", &storage.AuthState{
					ClientID:    "test-client",
					RedirectURI: "http://localhost/callback",
					Scopes:      []string{"openid"},
				})
			},
		},
		{
			name: "Username already exists",
			formData: url.Values{
				"username":        {"existinguser"},
				"email":           {"new@example.com"},
				"password":        {"Password123!"},
				"invitation_code": {"test-code"},
				"state":           {"test-state"},
			},
			expectedCode: http.StatusConflict,
			expectedBody: "Username already exists.",
			setup: func(p *OpenIDProvider, db *gormw.DB) {
				p.authStateStorage.Set("test-state", &storage.AuthState{
					ClientID:    "test-client",
					RedirectURI: "http://localhost/callback",
					Scopes:      []string{"openid"},
				})
				// Pre-create a user with the same username
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)
				existingUser := models.User{
					Username:       "existinguser",
					Email:          "existing@example.com",
					HashedPassword: string(hashedPassword),
				}
				db.Create(&existingUser)

				require.NoError(t, storage.AddInvitation(db, "test-code", "test-role"))
			},
		},
		{
			name: "Email already registered",
			formData: url.Values{
				"username":        {"newuser"},
				"email":           {"existing@example.com"},
				"password":        {"Password123!"},
				"invitation_code": {"test-code"},
				"state":           {"test-state"},
			},
			expectedCode: http.StatusConflict,
			expectedBody: "Email already registered.",
			setup: func(p *OpenIDProvider, db *gormw.DB) {
				p.authStateStorage.Set("test-state", &storage.AuthState{
					ClientID:    "test-client",
					RedirectURI: "http://localhost/callback",
					Scopes:      []string{"openid"},
				})
				// Pre-create a user with the same email
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)
				existingUser := models.User{
					Username:       "existinguser",
					Email:          "existing@example.com",
					HashedPassword: string(hashedPassword),
				}
				db.Create(&existingUser)

				require.NoError(t, storage.AddInvitation(db, "test-code", "test-role"))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p, db, router := setupTestProvider(t)
			if tc.setup != nil {
				tc.setup(p, db)
			}

			req, err := http.NewRequest(http.MethodPost, "/user/register", strings.NewReader(tc.formData.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			assert.Equal(t, tc.expectedCode, rec.Code, "Expected status %d, got %d. Body: %s", tc.expectedCode, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), tc.expectedBody)
		})
	}
}
