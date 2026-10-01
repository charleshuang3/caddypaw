package oidc

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormlog "gorm.io/gorm/logger"

	"github.com/charleshuang3/caddypaw/pkg/authn/gormw"
	"github.com/charleshuang3/caddypaw/pkg/authn/models"
	"github.com/charleshuang3/caddypaw/pkg/authn/storage"
	"github.com/charleshuang3/caddypaw/pkg/authn/testdata"
)

func setupTestProvider(t *testing.T, middlewares ...gin.HandlerFunc) (*OpenIDProvider, *gormw.DB, *gin.Engine) {
	t.Helper()

	cleanedErrorMessage = false

	database, err := gormw.Open(&gormw.Config{
		LogLevel: gormlog.Silent,
	})
	require.NoError(t, err)

	err = database.Migrate()
	require.NoError(t, err)

	// Create a test configuration
	config := &OIDCProviderConfig{
		Title:         "Test OIDC Provider",
		PrivateKeyPEM: testdata.PrivateKeyPEM,
		Issuer:        "http://localhost:8080/oauth2",
	}

	provider := NewOpenIDProvider(config, database)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	// Middlewares must be registered before the routes to apply to them.
	router.Use(middlewares...)
	testGroup := router.Group("/")
	provider.RegisterHandlers(testGroup)

	return provider, database, router
}

func setupTestForHandleAuthorize(t *testing.T, allowPasswordLogin bool) (*OpenIDProvider, *gormw.DB, *gin.Engine) {
	t.Helper()

	provider, db, router := setupTestProvider(t)

	// Use simplified login page template for testing
	useActualLoginPageTemplate(t)

	// Preload a test client
	testClient := models.Client{
		ClientID:           "test-client-id",
		Secret:             "test-client-secret",
		RedirectURIPrefixs: "http://localhost:8080/callback",
		AllowedScopes:      "openid profile email offline_access",
		AllowPasswordLogin: allowPasswordLogin,
		AllowGoogleLogin:   true,
	}
	err := db.Create(&testClient).Error
	require.NoError(t, err)

	// Add a conflict state
	provider.authStateStorage.Set("conflict-state", &storage.AuthState{})

	return provider, db, router
}

func TestHandleAuthorize_Error(t *testing.T) {
	tests := []struct {
		name            string
		queryParams     url.Values
		expectedStatus  int
		expectedErrCode string
	}{
		{
			name: "Missing client_id",
			queryParams: url.Values{
				"redirect_uri":  {"http://localhost:8080/callback"},
				"response_type": {"code"},
				"state":         {"valid-state"},
				"scope":         {"openid profile"},
			},
			expectedStatus: http.StatusBadRequest, // cannot redirect: client unknown
		},
		{
			name: "Missing redirect_uri",
			queryParams: url.Values{
				"client_id":     {"test-client-id"},
				"response_type": {"code"},
				"state":         {"valid-state"},
				"scope":         {"openid profile"},
			},
			expectedStatus: http.StatusBadRequest, // cannot redirect: redirect_uri unknown
		},
		{
			name: "Missing response_type",
			queryParams: url.Values{
				"client_id":    {"test-client-id"},
				"redirect_uri": {"http://localhost:8080/callback"},
				"state":        {"valid-state"},
				"scope":        {"openid profile"},
			},
			expectedStatus:  http.StatusFound,
			expectedErrCode: "invalid_request",
		},
		{
			name: "Invalid state format",
			queryParams: url.Values{
				"client_id":     {"test-client-id"},
				"redirect_uri":  {"http://localhost:8080/callback"},
				"response_type": {"code"},
				"state":         {"invalid@state"},
				"scope":         {"openid profile"},
			},
			expectedStatus:  http.StatusFound,
			expectedErrCode: "invalid_request",
		},
		{
			name: "Unsupported response type",
			queryParams: url.Values{
				"client_id":     {"test-client-id"},
				"redirect_uri":  {"http://localhost:8080/callback"},
				"response_type": {"token"},
				"state":         {"valid-state"},
				"scope":         {"openid profile"},
			},
			expectedStatus:  http.StatusFound,
			expectedErrCode: "invalid_request",
		},
		{
			name: "Conflict state",
			queryParams: url.Values{
				"client_id":     {"test-client-id"},
				"redirect_uri":  {"http://localhost:8080/callback"},
				"response_type": {"code"},
				"state":         {"conflict-state"},
				"scope":         {"openid profile"},
			},
			expectedStatus:  http.StatusFound,
			expectedErrCode: "invalid_request",
		},
		{
			name: "Client not found",
			queryParams: url.Values{
				"client_id":     {"non-existent-client"},
				"redirect_uri":  {"http://localhost:8080/callback"},
				"response_type": {"code"},
				"state":         {"valid-state"},
				"scope":         {"openid profile"},
			},
			expectedStatus: http.StatusBadRequest, // cannot redirect: client unknown
		},
		{
			name: "Invalid redirect URI",
			queryParams: url.Values{
				"client_id":     {"test-client-id"},
				"redirect_uri":  {"http://invalid-uri.com"},
				"response_type": {"code"},
				"state":         {"valid-state"},
				"scope":         {"openid profile"},
			},
			expectedStatus: http.StatusBadRequest, // cannot redirect: redirect_uri unverified
		},
		{
			name: "Invalid scope",
			queryParams: url.Values{
				"client_id":     {"test-client-id"},
				"redirect_uri":  {"http://localhost:8080/callback"},
				"response_type": {"code"},
				"state":         {"valid-state"},
				"scope":         {"invalid-scope"},
			},
			expectedStatus:  http.StatusFound,
			expectedErrCode: "invalid_scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, router := setupTestForHandleAuthorize(t, true)

			query := "?" + tt.queryParams.Encode()
			req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize"+query, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)

			if tt.expectedStatus == http.StatusFound {
				loc, err := url.Parse(rec.Header().Get("Location"))
				require.NoError(t, err)
				// Error must redirect to the client's registered redirect_uri.
				assert.Equal(t, "localhost:8080", loc.Host)
				q := loc.Query()
				assert.Equal(t, tt.expectedErrCode, q.Get("error"))
				assert.NotEmpty(t, q.Get("error_description"))
				if tt.queryParams.Get("state") != "" {
					assert.Equal(t, tt.queryParams.Get("state"), q.Get("state"))
				}
			} else {
				// 400 responses are plain text (no safe redirect target).
				assert.NotEmpty(t, rec.Body.String())
			}
		})
	}
}

// TestHandleAuthorize_OptionalParams verifies state and scope are optional.
func TestHandleAuthorize_OptionalParams(t *testing.T) {
	provider, _, router := setupTestForHandleAuthorize(t, true)

	queryParams := url.Values{
		"client_id":     {"test-client-id"},
		"redirect_uri":  {"http://localhost:8080/callback"},
		"response_type": {"code"},
		// no state, no scope
	}

	query := "?" + queryParams.Encode()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize"+query, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "Body: %s", rec.Body.String())

	// A generated state must have been stored with the client's default scopes.
	// Extract it from the login page's hidden state input.
	stateRE := regexp.MustCompile(`name="state" value="([^"]+)"`)
	m := stateRE.FindStringSubmatch(rec.Body.String())
	require.NotNil(t, m, "expected a state input on the login page")

	authState, ok := provider.authStateStorage.Get(m[1])
	require.True(t, ok, "expected the generated state to be stored")
	assert.Equal(t, "test-client-id", authState.ClientID)
	assert.Equal(t, "http://localhost:8080/callback", authState.RedirectURI)
	assert.Contains(t, authState.Scopes, "openid")
}

func TestHandleAuthorize_Success_LoginPage(t *testing.T) {
	provider, _, router := setupTestForHandleAuthorize(t, true)

	// Valid query parameters for a success case
	queryParams := url.Values{
		"client_id":     {"test-client-id"},
		"redirect_uri":  {"http://localhost:8080/callback"},
		"response_type": {"code"},
		"state":         {"valid-state"},
		"scope":         {"openid profile"},
	}

	query := "?" + queryParams.Encode()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize"+query, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Expect a login page
	assert.Equal(t, http.StatusOK, rec.Code)

	body, err := io.ReadAll(rec.Body)
	require.NoError(t, err)

	content := string(body)
	assert.Contains(t, content, provider.config.Title, "RenderLoginPage() output should contain title")
	assert.Contains(t, content, queryParams["state"][0], "RenderLoginPage() output should contain state")
}

func TestHandleAuthorize_Success_Redirect(t *testing.T) {
	_, _, router := setupTestForHandleAuthorize(t, false)

	// Valid query parameters for a success case
	queryParams := url.Values{
		"client_id":     {"test-client-id"},
		"redirect_uri":  {"http://localhost:8080/callback"},
		"response_type": {"code"},
		"state":         {"valid-state"},
		"scope":         {"openid profile"},
	}

	query := "?" + queryParams.Encode()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize"+query, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Expect a redirect to google login
	assert.Equal(t, http.StatusFound, rec.Code)
}
