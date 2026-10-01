package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/charleshuang3/caddypaw/pkg/authn/gormw"
	"github.com/charleshuang3/caddypaw/pkg/authn/models"
)

type tokenInfo struct {
	Email   string
	Name    string
	Picture string
}

func fakeOIDCServer(t *testing.T, privateKey interface{}, token *tokenInfo) *httptest.Server {
	t.Helper()

	s := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			builder := jwt.NewBuilder().
				Subject("sub").
				Claim("email", token.Email).
				Claim("name", token.Name).
				Claim("picture", token.Picture)

			tok, err := builder.Build()
			require.NoError(t, err)

			signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), privateKey))
			require.NoError(t, err)

			tokenResp := struct {
				IDToken     string `json:"id_token"`
				AccessToken string `json:"access_token"`
			}{
				IDToken:     string(signed),
				AccessToken: "access-token",
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			err = json.NewEncoder(w).Encode(tokenResp)
			require.NoError(t, err)
		}),
	)

	return s
}

func setupTestForHandleGoogleCallback(t *testing.T, token *tokenInfo) (*OpenIDProvider, *gormw.DB, *gin.Engine) {
	t.Helper()

	p, db, router := setupTestProviderForLogin(t)

	// Start a fake oidc server serve token exchange endpoint
	serv := fakeOIDCServer(t, p.privateKey, token)

	p.config.SSO.Google = GoogleLogin{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	// replace oauth2RequestClient with the client to the fake server
	oauth2RequestClient = serv.Client()

	tokenExchangeEndpoint = serv.URL + "/token"

	t.Cleanup(func() {
		serv.Close()
		oauth2RequestClient = http.DefaultClient
		tokenExchangeEndpoint = ""
	})

	return p, db, router
}

func TestHandleGoogleCallback_Error(t *testing.T) {
	tests := []struct {
		name           string
		token          *tokenInfo
		queryParams    url.Values
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Missing code parameter",
			token:          &tokenInfo{},
			queryParams:    url.Values{"state": []string{"valid-state"}},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing required parameters",
		},
		{
			name:           "Missing state parameter",
			token:          &tokenInfo{},
			queryParams:    url.Values{"code": []string{"auth-code"}},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing required parameters",
		},
		{
			name:           "Invalid state",
			token:          &tokenInfo{},
			queryParams:    url.Values{"code": []string{"auth-code"}, "state": []string{"invalid-state"}},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid state",
		},
		{
			name: "User not registered",
			token: &tokenInfo{
				Email:   "unregistered@example.com",
				Name:    "Unregistered User",
				Picture: "http://example.com/unregistered.jpg",
			},
			queryParams:    url.Values{"code": []string{"auth-code"}, "state": []string{"valid-state-for-login"}},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "User not registered",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, router := setupTestForHandleGoogleCallback(t, tt.token)

			req, err := http.NewRequest(http.MethodGet, "/sso/google/callback?"+tt.queryParams.Encode(), nil)
			require.NoError(t, err)

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			require.Equal(t, tt.expectedStatus, rec.Code)
			require.Contains(t, rec.Body.String(), tt.expectedBody)
		})
	}
}

func TestHandleGoogleCallback(t *testing.T) {
	token := &tokenInfo{
		Email:   "existing@example.com",
		Name:    "Test User",
		Picture: "http://example.com/picture.jpg",
	}

	provider, db, router := setupTestForHandleGoogleCallback(t, token)

	queryParams := url.Values{
		"code":  []string{"auth-code"},
		"state": []string{"valid-state-for-login"},
	}
	req, err := http.NewRequest(http.MethodGet, "/sso/google/callback?"+queryParams.Encode(), nil)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Check for redirect status
	require.Equal(t, http.StatusFound, rec.Code)

	// Check redirect location
	locationHeader := rec.Header().Get("Location")
	require.NotEmpty(t, locationHeader)
	require.True(t, strings.HasPrefix(locationHeader, "http://localhost/callback?"))

	// Parse redirect URL to extract code and state
	parsedURL, err := url.Parse(locationHeader)
	require.NoError(t, err)
	query := parsedURL.Query()
	codeParam := query.Get("code")
	stateParam := query.Get("state")
	require.NotEmpty(t, codeParam)
	require.Equal(t, "valid-state-for-login", stateParam)

	// Verify the code is stored
	code, ok := provider.authCodeStorage.Get(codeParam)
	require.True(t, ok)
	require.Equal(t, "test-client", code.ClientID)
	require.Equal(t, "http://localhost/callback", code.RedirectURI)
	require.Contains(t, code.Scopes, "openid")

	// Verify state was removed after use
	_, ok = provider.authStateStorage.Get("valid-state")
	require.False(t, ok)

	// Verify user data was updated in database
	var updatedUser models.User
	err = db.Where("email = ?", token.Email).First(&updatedUser).Error
	require.NoError(t, err)
	require.Equal(t, token.Name, updatedUser.Name)
	require.Equal(t, token.Picture, updatedUser.Picture)
}
