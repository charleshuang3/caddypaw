package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/charleshuang3/caddypaw/pkg/authn/gormw"
	"github.com/charleshuang3/caddypaw/pkg/authn/models"
	"github.com/charleshuang3/caddypaw/pkg/authn/storage"
)

func TestGenAccessToken(t *testing.T) {
	provider, _, router := setupTestProvider(t)

	// Start a test server to serve the JWKS
	ts := httptest.NewServer(router)
	defer ts.Close()

	// Use coreos/go-oidc to fetch the JWKS
	ctx := context.Background()
	keySet := gooidc.NewRemoteKeySet(ctx, ts.URL+"/oauth2/.well-known/jwks.json")

	user := &models.User{
		Username: "testuser",
		Roles:    "user",
	}
	client := &models.Client{
		ClientID:        "testclient",
		AccessTokenTTL:  3600,
		RefreshTokenTTL: 7200,
	}
	scopes := []string{"openid", "profile"}

	token, err := provider.genAccessToken(user, client, scopes)
	require.NoError(t, err, "Expected no error when generating access token")

	// Verify the token using go-oidc
	verifier := gooidc.NewVerifier(provider.config.Issuer, keySet, &gooidc.Config{SkipClientIDCheck: true})

	idToken, err := verifier.Verify(ctx, token)
	require.NoError(t, err, "Expected no error when verifying access token")
	assert.NotNil(t, idToken, "Expected non-nil ID token after verification")

	// Verify claims
	var claims struct {
		Roles string `json:"roles"`
		Scope string `json:"scope"`
	}
	err = idToken.Claims(&claims)
	require.NoError(t, err, "Expected no error when extracting claims")

	assert.Equal(t, user.Username, idToken.Subject, "Expected subject to match username")
	assert.Contains(t, idToken.Audience, client.ClientID, "Expected audience to contain client ID")
	assert.Equal(t, user.Roles, claims.Roles, "Expected roles claim to match user roles")
	assert.Equal(t, strings.Join(scopes, " "), claims.Scope, "Expected scope claim to match scopes")
}

func TestGenRefreshToken(t *testing.T) {
	provider, _, router := setupTestProvider(t)

	// Start a test server to serve the JWKS
	ts := httptest.NewServer(router)
	defer ts.Close()

	// Use coreos/go-oidc to fetch the JWKS
	ctx := context.Background()
	keySet := gooidc.NewRemoteKeySet(ctx, ts.URL+"/oauth2/.well-known/jwks.json")
	verifier := gooidc.NewVerifier(provider.config.Issuer, keySet, &gooidc.Config{SkipClientIDCheck: true})

	user := &models.User{
		Username: "testuser",
		Roles:    "user",
	}
	client := &models.Client{
		ClientID:        "testclient",
		AccessTokenTTL:  3600,
		RefreshTokenTTL: 7200,
	}
	scopes := []string{"openid", "profile", "offline_access"}

	token, err := provider.genRefreshToken(user, client, scopes)
	require.NoError(t, err, "Expected no error when generating refresh token")

	// Verify the token using go-oidc
	idToken, err := verifier.Verify(ctx, token)
	require.NoError(t, err, "Expected no error when verifying refresh token")
	assert.NotNil(t, idToken, "Expected non-nil ID token after verification")

	// Verify claims
	var claims struct {
		Scope string `json:"scope"`
	}
	err = idToken.Claims(&claims)
	require.NoError(t, err, "Expected no error when extracting claims")

	assert.Equal(t, user.Username, idToken.Subject, "Expected subject to match username")
	assert.Contains(t, idToken.Audience, client.ClientID, "Expected audience to contain client ID")
	assert.Equal(t, strings.Join(scopes, " "), claims.Scope, "Expected scope claim to match scopes")
}

func TestGenIDToken(t *testing.T) {
	provider, _, router := setupTestProvider(t)

	// Start a test server to serve the JWKS
	ts := httptest.NewServer(router)
	defer ts.Close()

	// Use coreos/go-oidc to fetch the JWKS
	ctx := context.Background()
	keySet := gooidc.NewRemoteKeySet(ctx, ts.URL+"/oauth2/.well-known/jwks.json")
	verifier := gooidc.NewVerifier(provider.config.Issuer, keySet, &gooidc.Config{SkipClientIDCheck: true})

	user := &models.User{
		Username: "testuser",
		Roles:    "user",
		Email:    "testuser@example.com",
		GoogleID: "google123",
		Picture:  "https://example.com/picture.jpg",
	}
	client := &models.Client{
		ClientID:        "testclient",
		AccessTokenTTL:  3600,
		RefreshTokenTTL: 7200,
	}
	scopes := []string{"openid", "profile", "email"}

	token, err := provider.genIDToken(user, client, scopes)
	require.NoError(t, err, "Expected no error when generating ID token")

	// Verify the token using go-oidc
	idToken, err := verifier.Verify(ctx, token)
	require.NoError(t, err, "Expected no error when verifying ID token")
	assert.NotNil(t, idToken, "Expected non-nil ID token after verification")

	// Verify claims
	var claims struct {
		Roles    string `json:"roles"`
		Scope    string `json:"scope"`
		Email    string `json:"email"`
		GoogleID string `json:"google_id"`
		Picture  string `json:"picture"`
	}
	err = idToken.Claims(&claims)
	require.NoError(t, err, "Expected no error when extracting claims")

	assert.Equal(t, user.Username, idToken.Subject, "Expected subject to match username")
	assert.Contains(t, idToken.Audience, client.ClientID, "Expected audience to contain client ID")
	assert.Equal(t, user.Roles, claims.Roles, "Expected roles claim to match user roles")
	assert.Equal(t, strings.Join(scopes, " "), claims.Scope, "Expected scope claim to match scopes")
	assert.Equal(t, user.Email, claims.Email, "Expected email claim to match user email")
	assert.Equal(t, user.GoogleID, claims.GoogleID, "Expected google_id claim to match user Google ID")
	assert.Equal(t, user.Picture, claims.Picture, "Expected picture claim to match user picture")
}

func TestHandleToken_Error(t *testing.T) {
	tests := []struct {
		name           string
		grantType      string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Empty grant_type",
			grantType:      "",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "require form value grant_type",
		},
		{
			name:           "Unsupported grant_type",
			grantType:      "unsupported_grant",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Unsupported grant type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, router := setupTestProvider(t)

			// Create a request with the specified grant_type
			formData := url.Values{
				"grant_type": {tt.grantType},
			}
			req, err := http.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(formData.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code, "Expected status %d, got %d. Body: %s", tt.expectedStatus, rec.Code, rec.Body.String())
			assert.Equal(t, tt.expectedBody, rec.Body.String(), "Expected body %q, got %q", tt.expectedBody, rec.Body.String())
		})
	}
}

func setupTestProviderForTokenRequest(t *testing.T) (*OpenIDProvider, *gormw.DB, *gin.Engine) {
	t.Helper()

	provider, db, router := setupTestProvider(t)

	// Pre-create a user for tests
	existingUser := models.User{
		Username: "existinguser",
		Name:     "Existing User",
		Email:    "existing@example.com",
		Picture:  "https://example.com/picture.jpg",
		GoogleID: "google456",
		Roles:    "user",
	}
	err := db.Create(&existingUser).Error
	require.NoError(t, err)

	existingClient := models.Client{
		ClientID:        "existing-client",
		Secret:          "correct-secret",
		AccessTokenTTL:  600,
		RefreshTokenTTL: 24 * 3600,
	}
	err = db.Create(&existingClient).Error
	require.NoError(t, err)

	return provider, db, router
}

func TestHandleTokenAuthorizationCode_Success(t *testing.T) {
	tests := []struct {
		name            string
		scopes          []string
		expectedID      bool
		expectedRefresh bool
	}{
		{
			name:            "openid and profile scopes",
			scopes:          []string{"openid", "profile"},
			expectedID:      true,
			expectedRefresh: false,
		},
		{
			name:            "openid, profile, and offline_access scopes",
			scopes:          []string{"openid", "profile", "offline_access"},
			expectedID:      true,
			expectedRefresh: true,
		},
		{
			name:            "offline_access scope only",
			scopes:          []string{"offline_access"},
			expectedID:      false,
			expectedRefresh: true,
		},
		{
			name:            "no openid or offline_access scopes",
			scopes:          []string{"profile"},
			expectedID:      false,
			expectedRefresh: false,
		},
		{
			name:            "empty scopes",
			scopes:          []string{},
			expectedID:      false,
			expectedRefresh: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, db, router := setupTestProviderForTokenRequest(t)

			// Pre-create an auth code
			authCodeValue := "valid-auth-code-" + strings.Join(tt.scopes, "-")
			provider.authCodeStorage.Set(authCodeValue, &storage.AuthCode{
				ClientID: "existing-client",
				UserID:   1,
				Scopes:   tt.scopes,
			})

			formData := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {authCodeValue},
				"client_id":     {"existing-client"},
				"client_secret": {"correct-secret"},
			}

			req, err := http.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(formData.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code, "Expected status %d, got %d. Body: %s", http.StatusOK, rec.Code, rec.Body.String())

			var resp handleTokenResponse
			err = json.Unmarshal(rec.Body.Bytes(), &resp)
			require.NoError(t, err, "Failed to unmarshal response body")

			assert.NotEmpty(t, resp.AccessToken, "Expected non-empty access_token")
			assert.Equal(t, strings.Join(tt.scopes, " "), resp.Scope, "Expected scope to match")
			assert.Equal(t, "Bearer", resp.TokenType, "Expected token_type to be Bearer")
			assert.Greater(t, resp.ExpiresIn, 0, "Expected expires_in to be greater than 0")

			if tt.expectedID {
				assert.NotEmpty(t, resp.IDToken, "Expected non-empty id_token")
			} else {
				assert.Empty(t, resp.IDToken, "Expected empty id_token")
			}

			if tt.expectedRefresh {
				assert.NotEmpty(t, resp.RefreshToken, "Expected non-empty refresh_token")
				// Verify the refresh token was saved in the database
				refreshTokenSign := strings.Split(resp.RefreshToken, ".")[2]
				refreshToken, err := storage.GetRefreshTokenBySign(db, refreshTokenSign)
				require.NoError(t, err, "Expected refresh token to be found in database")
				assert.NotNil(t, refreshToken, "Expected non-nil refresh token from database")
				assert.False(t, refreshToken.Used, "Expected refresh token to not be marked as used initially")
				assert.False(t, refreshToken.Revoked, "Expected refresh token to not be marked as revoked")
			} else {
				assert.Empty(t, resp.RefreshToken, "Expected empty refresh_token")
			}

			// Verify the auth code was removed after use
			_, ok := provider.authCodeStorage.Get(authCodeValue)
			assert.False(t, ok, "Expected auth code to be removed after use")
		})
	}
}

func TestHandleTokenRefreshToken_Success(t *testing.T) {
	tests := []struct {
		name       string
		scopes     []string
		expectedID bool
	}{
		{
			name:       "openid, profile, and offline_access scopes",
			scopes:     []string{"openid", "profile", "offline_access"},
			expectedID: true,
		},
		{
			name:       "offline_access scope only",
			scopes:     []string{"offline_access"},
			expectedID: false,
		},
		{
			name:       "offline_access and profile scopes",
			scopes:     []string{"offline_access", "profile"},
			expectedID: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, db, router := setupTestProviderForTokenRequest(t)

			// Create a valid refresh token and add it to the database
			user, err := storage.GetUserByID(db, 1) // Corresponds to the existinguser in setupTestProviderForTokenRequest
			require.NoError(t, err)
			client := &models.Client{ClientID: "existing-client", RefreshTokenTTL: 3600}
			refreshTokenValue, err := provider.genRefreshToken(user, client, tt.scopes)
			require.NoError(t, err)

			refreshTokenSign := strings.Split(refreshTokenValue, ".")[2]
			err = storage.AddRefreshToken(db, &models.RefreshToken{
				Sign:      refreshTokenSign,
				UserID:    user.ID,
				ExpiresAt: time.Now().Add(time.Hour),
			})
			require.NoError(t, err)

			formData := url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {refreshTokenValue},
				"client_id":     {"existing-client"},
				"client_secret": {"correct-secret"},
			}

			req, err := http.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(formData.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code, "Expected status %d, got %d. Body: %s", http.StatusOK, rec.Code, rec.Body.String())

			var resp handleTokenResponse
			err = json.Unmarshal(rec.Body.Bytes(), &resp)
			require.NoError(t, err, "Failed to unmarshal response body")

			assert.NotEmpty(t, resp.AccessToken, "Expected non-empty access_token")
			assert.NotEmpty(t, resp.RefreshToken, "Expected non-empty refresh_token") // Refresh token grant always returns a new refresh token
			assert.Equal(t, strings.Join(tt.scopes, " "), resp.Scope, "Expected scope to match")
			assert.Equal(t, "Bearer", resp.TokenType, "Expected token_type to be Bearer")
			assert.Greater(t, resp.ExpiresIn, 0, "Expected expires_in to be greater than 0")

			if tt.expectedID {
				assert.NotEmpty(t, resp.IDToken, "Expected non-empty id_token")
			} else {
				assert.Empty(t, resp.IDToken, "Expected empty id_token")
			}

			// Verify the old refresh token was marked as used
			oldRefreshToken, err := storage.GetRefreshTokenBySign(db, refreshTokenSign)
			require.NoError(t, err, "Expected old refresh token to be found in database")
			assert.NotNil(t, oldRefreshToken, "Expected non-nil old refresh token from database")
			assert.True(t, oldRefreshToken.Used, "Expected old refresh token to be marked as used")

			// Verify the new refresh token was saved in the database
			newRefreshTokenSign := strings.Split(resp.RefreshToken, ".")[2]
			newRefreshToken, err := storage.GetRefreshTokenBySign(db, newRefreshTokenSign)
			require.NoError(t, err, "Expected new refresh token to be found in database")
			assert.NotNil(t, newRefreshToken, "Expected non-nil new refresh token from database")
			assert.False(t, newRefreshToken.Used, "Expected new refresh token to not be marked as used initially")
			assert.False(t, newRefreshToken.Revoked, "Expected new refresh token to not be marked as revoked")
		})
	}
}

func TestHandleTokenAuthorizationCode_Error(t *testing.T) {
	tests := []struct {
		name           string
		formData       url.Values
		setup          func(*testing.T, *OpenIDProvider, *gormw.DB, url.Values) // Optional setup for specific test cases
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "Missing code",
			formData: url.Values{
				"client_id":     {"test-client"},
				"client_secret": {"test-secret"},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing required parameters",
		},
		{
			name: "Missing client_id",
			formData: url.Values{
				"code":          {"some-code"},
				"client_secret": {"test-secret"},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing required parameters",
		},
		{
			name: "Missing client_secret",
			formData: url.Values{
				"code":      {"some-code"},
				"client_id": {"test-client"},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing required parameters",
		},
		{
			name: "Invalid authorization code",
			formData: url.Values{
				"code":          {"invalid-code"},
				"client_id":     {"test-client"},
				"client_secret": {"test-secret"},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid authorization code",
		},
		{
			name: "Invalid client ID (does not match auth code)",
			formData: url.Values{
				"code":          {"valid-code"},
				"client_id":     {"wrong-client"},
				"client_secret": {"test-secret"},
			},
			setup: func(t *testing.T, p *OpenIDProvider, db *gormw.DB, formData url.Values) {
				p.authCodeStorage.Set("valid-code", &storage.AuthCode{
					ClientID: "existing-client",
					UserID:   1,
					Scopes:   []string{"openid"},
				})
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid client ID",
		},
		{
			name: "Client not found",
			formData: url.Values{
				"code":          {"valid-code"},
				"client_id":     {"non-existent-client"},
				"client_secret": {"test-secret"},
			},
			setup: func(t *testing.T, p *OpenIDProvider, db *gormw.DB, formData url.Values) {
				p.authCodeStorage.Set("valid-code", &storage.AuthCode{
					ClientID: "non-existent-client",
					UserID:   1,
					Scopes:   []string{"openid"},
				})
				// Do not create the client in the database
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Client not found",
		},
		{
			name: "Invalid client secret",
			formData: url.Values{
				"code":          {"valid-code"},
				"client_id":     {"existing-client"},
				"client_secret": {"wrong-secret"},
			},
			setup: func(t *testing.T, p *OpenIDProvider, db *gormw.DB, formData url.Values) {
				p.authCodeStorage.Set("valid-code", &storage.AuthCode{
					ClientID: "existing-client",
					UserID:   1,
					Scopes:   []string{"openid"},
				})
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid client secret",
		},
		{
			name: "User not found",
			formData: url.Values{
				"code":          {"valid-code"},
				"client_id":     {"existing-client"},
				"client_secret": {"correct-secret"},
			},
			setup: func(t *testing.T, p *OpenIDProvider, db *gormw.DB, formData url.Values) {
				p.authCodeStorage.Set("valid-code", &storage.AuthCode{
					ClientID: "existing-client",
					UserID:   999, // Non-existent user ID
					Scopes:   []string{"openid"},
				})
				// Do not create user with ID 999
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, db, router := setupTestProviderForTokenRequest(t)
			if tt.setup != nil {
				tt.setup(t, provider, db, tt.formData)
			}

			tt.formData.Add("grant_type", "authorization_code")

			req, err := http.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(tt.formData.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code, "Expected status %d, got %d. Body: %s", tt.expectedStatus, rec.Code, rec.Body.String())
			assert.Equal(t, tt.expectedBody, rec.Body.String(), "Expected body %q, got %q", tt.expectedBody, rec.Body.String())
		})
	}
}

func TestHandleTokenRefreshToken_Error(t *testing.T) {
	tests := []struct {
		name           string
		formData       url.Values
		setup          func(*testing.T, *OpenIDProvider, *gormw.DB, url.Values) // Optional setup for specific test cases
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "Missing refresh_token",
			formData: url.Values{
				"client_id":     {"test-client"},
				"client_secret": {"test-secret"},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing required parameters",
		},
		{
			name: "Missing client_id",
			formData: url.Values{
				"refresh_token": {"some-token"},
				"client_secret": {"test-secret"},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing required parameters",
		},
		{
			name: "Missing client_secret",
			formData: url.Values{
				"refresh_token": {"some-token"},
				"client_id":     {"test-client"},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing required parameters",
		},
		{
			name: "Invalid refresh token format",
			formData: url.Values{
				"refresh_token": {"invalid-format"},
				"client_id":     {"test-client"},
				"client_secret": {"test-secret"},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid refresh token: format",
		},
		{
			name: "Invalid refresh token signature",
			formData: url.Values{
				"refresh_token": {"invalid-signature"},
				"client_id":     {"test-client"},
				"client_secret": {"test-secret"},
			},
			setup: func(t *testing.T, p *OpenIDProvider, db *gormw.DB, formData url.Values) {
				token, err := jwt.NewBuilder().
					Issuer(p.config.Issuer).
					IssuedAt(time.Now().Add(-time.Minute)).
					Expiration(time.Now().Add(time.Minute)).
					Audience([]string{"existing-client"}).
					Subject("existinguser").
					Claim("scope", "offline_access").
					Build()
				require.NoError(t, err)
				signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), p.privateKey))
				require.NoError(t, err)
				formData.Set("refresh_token", string(signed)+"1") // make signature invalid
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid refresh token: signature",
		},
		{
			name: "Expired refresh token",
			formData: url.Values{
				"refresh_token": {"expired-token"},
				"client_id":     {"existing-client"},
				"client_secret": {"test-secret"},
			},
			setup: func(t *testing.T, p *OpenIDProvider, db *gormw.DB, formData url.Values) {
				// Create an expired token
				token, err := jwt.NewBuilder().
					Issuer(p.config.Issuer).
					IssuedAt(time.Now().Add(-time.Hour)).     // Issued an hour ago
					Expiration(time.Now().Add(-time.Minute)). // expired
					Audience([]string{"existing-client"}).
					Subject("existinguser").
					Claim("scope", "offline_access").
					Build()
				require.NoError(t, err)
				signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), p.privateKey))
				require.NoError(t, err)
				formData.Set("refresh_token", string(signed))

				// Add the refresh token to the database
				refreshTokenSign := strings.Split(string(signed), ".")[2]
				err = storage.AddRefreshToken(db, &models.RefreshToken{
					Sign:   refreshTokenSign,
					UserID: 1,
				})
				require.NoError(t, err)
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid refresh token: expired",
		},
		{
			name: "Invalid client ID (does not match token audience)",
			formData: url.Values{
				"refresh_token": {"valid-token-wrong-audience"},
				"client_id":     {"wrong-client"},
				"client_secret": {"test-secret"},
			},
			setup: func(t *testing.T, p *OpenIDProvider, db *gormw.DB, formData url.Values) {
				// Create a token with a different audience
				token, err := p.genRefreshToken(&models.User{Username: "existinguser"}, &models.Client{ClientID: "existing-client", RefreshTokenTTL: 3600}, []string{"offline_access"})
				require.NoError(t, err)
				formData.Set("refresh_token", token)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid refresh token: audience",
		},
		{
			name: "No Expiration refresh token",
			formData: url.Values{
				"refresh_token": {"expired-token"},
				"client_id":     {"existing-client"},
				"client_secret": {"test-secret"},
			},
			setup: func(t *testing.T, p *OpenIDProvider, db *gormw.DB, formData url.Values) {
				// Create an token without Expiration
				token, err := jwt.NewBuilder().
					Issuer(p.config.Issuer).
					IssuedAt(time.Now().Add(-time.Hour)). // Issued an hour ago
					// No Expiration
					Audience([]string{"existing-client"}).
					Subject("existinguser").
					Claim("scope", "offline_access").
					Build()
				require.NoError(t, err)
				signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), p.privateKey))
				require.NoError(t, err)
				formData.Set("refresh_token", string(signed))

				// Add the refresh token to the database
				refreshTokenSign := strings.Split(string(signed), ".")[2]
				err = storage.AddRefreshToken(db, &models.RefreshToken{
					Sign:   refreshTokenSign,
					UserID: 1,
				})
				require.NoError(t, err)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid refresh token: no expiration",
		},
		{
			name: "Invalid issuer",
			formData: url.Values{
				"refresh_token": {"invalid-issuer-token"},
				"client_id":     {"existing-client"},
				"client_secret": {"test-secret"},
			},
			setup: func(t *testing.T, p *OpenIDProvider, db *gormw.DB, formData url.Values) {
				// Create a token with a different issuer
				token, err := jwt.NewBuilder().
					Issuer("invalid-issuer").
					IssuedAt(time.Now()).
					Expiration(time.Now().Add(time.Hour)).
					Audience([]string{"existing-client"}).
					Subject("testuser").
					Claim("scope", "offline_access").
					Build()
				require.NoError(t, err)
				signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), p.privateKey))
				require.NoError(t, err)
				formData.Set("refresh_token", string(signed))

				// Add the refresh token to the database
				refreshTokenSign := strings.Split(string(signed), ".")[2]
				err = storage.AddRefreshToken(db, &models.RefreshToken{
					Sign:   refreshTokenSign,
					UserID: 1,
				})
				require.NoError(t, err)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid refresh token: issuer",
		},
		{
			name: "Refresh token not found in database",
			formData: url.Values{
				"refresh_token": {"valid-token-not-in-db"},
				"client_id":     {"existing-client"},
				"client_secret": {"test-secret"},
			},
			setup: func(t *testing.T, p *OpenIDProvider, db *gormw.DB, formData url.Values) {
				// Create a valid token but don't add it to the database
				token, err := p.genRefreshToken(&models.User{Username: "testuser"}, &models.Client{ClientID: "existing-client", RefreshTokenTTL: 3600}, []string{"offline_access"})
				require.NoError(t, err)
				formData.Set("refresh_token", token)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid refresh token: not found",
		},
		{
			name: "Revoked refresh token",
			formData: url.Values{
				"refresh_token": {"revoked-token"},
				"client_id":     {"existing-client"},
				"client_secret": {"test-secret"},
			},
			setup: func(t *testing.T, p *OpenIDProvider, db *gormw.DB, formData url.Values) {
				// Create a valid token and mark it as revoked in the database
				token, err := p.genRefreshToken(&models.User{Username: "testuser"}, &models.Client{ClientID: "existing-client", RefreshTokenTTL: 3600}, []string{"offline_access"})
				require.NoError(t, err)
				formData.Set("refresh_token", token)

				refreshTokenSign := strings.Split(token, ".")[2]
				err = storage.AddRefreshToken(db, &models.RefreshToken{
					Sign:    refreshTokenSign,
					UserID:  1,
					Revoked: true,
				})
				require.NoError(t, err)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Revoked refresh token",
		},
		{
			name: "Used refresh token (replay attack)",
			formData: url.Values{
				"refresh_token": {"used-token"},
				"client_id":     {"existing-client"},
				"client_secret": {"test-secret"},
			},
			setup: func(t *testing.T, p *OpenIDProvider, db *gormw.DB, formData url.Values) {
				// Create a valid token and mark it as used in the database
				token, err := p.genRefreshToken(&models.User{Username: "testuser"}, &models.Client{ClientID: "existing-client", RefreshTokenTTL: 3600}, []string{"offline_access"})
				require.NoError(t, err)
				formData.Set("refresh_token", token)

				refreshTokenSign := strings.Split(token, ".")[2]
				err = storage.AddRefreshToken(db, &models.RefreshToken{
					Sign:   refreshTokenSign,
					UserID: 1,
					Used:   true,
				})
				require.NoError(t, err)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Used refresh token",
		},
		{
			name: "Client not found",
			formData: url.Values{
				"refresh_token": {"valid-token"},
				"client_id":     {"non-existent-client"},
				"client_secret": {"test-secret"},
			},
			setup: func(t *testing.T, p *OpenIDProvider, db *gormw.DB, formData url.Values) {
				// Create a valid token
				token, err := p.genRefreshToken(&models.User{Username: "testuser"}, &models.Client{ClientID: "non-existent-client", RefreshTokenTTL: 3600}, []string{"offline_access"})
				require.NoError(t, err)
				formData.Set("refresh_token", token)

				// Add the refresh token to the database
				refreshTokenSign := strings.Split(token, ".")[2]
				err = storage.AddRefreshToken(db, &models.RefreshToken{
					Sign:   refreshTokenSign,
					UserID: 1,
				})
				require.NoError(t, err)
				// Do not create the client in the database
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Client not found",
		},
		{
			name: "Invalid client secret",
			formData: url.Values{
				"refresh_token": {"valid-token"},
				"client_id":     {"existing-client"},
				"client_secret": {"wrong-secret"},
			},
			setup: func(t *testing.T, p *OpenIDProvider, db *gormw.DB, formData url.Values) {
				// Create a valid token
				token, err := p.genRefreshToken(&models.User{Username: "testuser"}, &models.Client{ClientID: "existing-client", RefreshTokenTTL: 3600}, []string{"offline_access"})
				require.NoError(t, err)
				formData.Set("refresh_token", token)

				// Add the refresh token to the database
				refreshTokenSign := strings.Split(token, ".")[2]
				err = storage.AddRefreshToken(db, &models.RefreshToken{
					Sign:   refreshTokenSign,
					UserID: 1,
				})
				require.NoError(t, err)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid client secret",
		},
		{
			name: "User not found",
			formData: url.Values{
				"refresh_token": {"valid-token"},
				"client_id":     {"existing-client"},
				"client_secret": {"correct-secret"},
			},
			setup: func(t *testing.T, p *OpenIDProvider, db *gormw.DB, formData url.Values) {
				// Create a valid token
				token, err := p.genRefreshToken(&models.User{Username: "testuser"}, &models.Client{ClientID: "existing-client", RefreshTokenTTL: 3600}, []string{"offline_access"})
				require.NoError(t, err)
				formData.Set("refresh_token", token)

				// Add the refresh token to the database with a non-existent user ID
				refreshTokenSign := strings.Split(token, ".")[2]
				err = storage.AddRefreshToken(db, &models.RefreshToken{
					Sign:      refreshTokenSign,
					UserID:    999, // Non-existent user ID
					ExpiresAt: time.Now().Add(time.Hour),
				})
				require.NoError(t, err)
				// Do not create user with ID 999
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, db, router := setupTestProviderForTokenRequest(t)
			if tt.setup != nil {
				tt.setup(t, provider, db, tt.formData)
			}

			tt.formData.Add("grant_type", "refresh_token")

			req, err := http.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(tt.formData.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code, "Expected status %d, got %d. Body: %s", tt.expectedStatus, rec.Code, rec.Body.String())
			assert.Equal(t, tt.expectedBody, rec.Body.String(), "Expected body %q, got %q", tt.expectedBody, rec.Body.String())
		})
	}
}
