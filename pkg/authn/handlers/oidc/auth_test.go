package oidc

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func setupTestProvider(t *testing.T) (*OpenIDProvider, *gormw.DB, *gin.Engine) {
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
		name           string
		queryParams    url.Values
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "Missing client_id",
			queryParams: url.Values{
				"redirect_uri":  {"http://localhost:8080/callback"},
				"response_type": {"code"},
				"state":         {"valid-state"},
				"scope":         {"openid profile"},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing required parameters",
		},
		{
			name: "Missing redirect_uri",
			queryParams: url.Values{
				"client_id":     {"test-client-id"},
				"response_type": {"code"},
				"state":         {"valid-state"},
				"scope":         {"openid profile"},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing required parameters",
		},
		{
			name: "Missing response_type",
			queryParams: url.Values{
				"client_id":    {"test-client-id"},
				"redirect_uri": {"http://localhost:8080/callback"},
				"state":        {"valid-state"},
				"scope":        {"openid profile"},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing required parameters",
		},
		{
			name: "Missing state",
			queryParams: url.Values{
				"client_id":     {"test-client-id"},
				"redirect_uri":  {"http://localhost:8080/callback"},
				"response_type": {"code"},
				"scope":         {"openid profile"},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing required parameters",
		},
		{
			name: "No scope provided",
			queryParams: url.Values{
				"client_id":     {"test-client-id"},
				"redirect_uri":  {"http://localhost:8080/callback"},
				"response_type": {"code"},
				"state":         {"valid-state"},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing required parameters",
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
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid state parameter format",
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
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Unsupported response type, only 'code' is supported",
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
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Conflict state",
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
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Client not found",
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
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid redirect URI",
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
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid scope",
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
			assert.Equal(t, tt.expectedBody, rec.Body.String())
		})
	}
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
