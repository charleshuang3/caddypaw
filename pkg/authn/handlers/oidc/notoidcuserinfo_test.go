package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/charleshuang3/caddypaw/pkg/authn/gormw"
	"github.com/charleshuang3/caddypaw/pkg/authn/models"
)

func setupTestForHandleNotOIDCUserInfo(t *testing.T) (*OpenIDProvider, *gormw.DB, *gin.Engine) {
	t.Helper()

	p, db, router := setupTestProvider(t)

	// Pre-create a user for tests
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)
	require.NoError(t, err)
	err = db.Create(&models.User{
		Username:       "existinguser",
		Email:          "existing@example.com",
		HashedPassword: string(hashedPassword),
	}).Error
	require.NoError(t, err)

	// client does not support http basic auth
	err = db.Create(&models.Client{
		ClientID:           "test-client-normal",
		Secret:             "test-secret",
		ClientName:         "Test Client",
		AllowHTTPBasicAuth: false,
	}).Error
	require.NoError(t, err)

	// client supports http basic auth
	err = db.Create(&models.Client{
		ClientID:           "test-client-http-basic",
		Secret:             "test-secret",
		ClientName:         "Test Client",
		AllowHTTPBasicAuth: true,
		AccessTokenTTL:     3600,
	}).Error
	require.NoError(t, err)

	return p, db, router
}

func TestHandleNotOIDCUserInfo(t *testing.T) {
	tests := []struct {
		name           string
		clientID       string
		clientSecret   string
		username       string
		password       string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Valid credentials",
			clientID:       "test-client-http-basic",
			clientSecret:   "test-secret",
			username:       "existinguser",
			password:       "correctpassword",
			expectedStatus: http.StatusOK,
			expectedBody:   `{"username":"existinguser","name":"","email":"existing@example.com","roles":"","picture":"","exp":`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, router := setupTestForHandleNotOIDCUserInfo(t)

			formData := url.Values{
				"client_id":     {tt.clientID},
				"client_secret": {tt.clientSecret},
				"username":      {tt.username},
				"password":      {tt.password},
			}

			req, err := http.NewRequest(http.MethodPost, "/user/info", strings.NewReader(formData.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)

			got := &handleNotOIDCUserInfoResponse{}
			err = json.NewDecoder(rec.Body).Decode(got)
			require.NoError(t, err)

			assert.Equal(t, tt.username, got.Username)
			assert.Less(t, time.Now().Unix(), got.Expiration)
		})
	}
}

func TestHandleNotOIDCUserInfo_Error(t *testing.T) {
	tests := []struct {
		name           string
		clientID       string
		clientSecret   string
		username       string
		password       string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Missing parameters",
			clientID:       "",
			clientSecret:   "",
			username:       "",
			password:       "",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing required parameters",
		},
		{
			name:           "Invalid client ID",
			clientID:       "invalid-client",
			clientSecret:   "test-secret",
			username:       "existinguser",
			password:       "correctpassword",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid client ID",
		},
		{
			name:           "Invalid client secret",
			clientID:       "test-client-http-basic",
			clientSecret:   "wrong-secret",
			username:       "existinguser",
			password:       "correctpassword",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid client secret",
		},
		{
			name:           "Client does not allow HTTP basic auth",
			clientID:       "test-client-normal",
			clientSecret:   "test-secret",
			username:       "existinguser",
			password:       "correctpassword",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Client does not allow HTTP basic auth",
		},
		{
			name:           "Invalid username",
			clientID:       "test-client-http-basic",
			clientSecret:   "test-secret",
			username:       "nonexistentuser",
			password:       "correctpassword",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid username",
		},
		{
			name:           "Invalid password",
			clientID:       "test-client-http-basic",
			clientSecret:   "test-secret",
			username:       "existinguser",
			password:       "wrongpassword",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, router := setupTestForHandleNotOIDCUserInfo(t)

			formData := url.Values{
				"client_id":     {tt.clientID},
				"client_secret": {tt.clientSecret},
				"username":      {tt.username},
				"password":      {tt.password},
			}

			req, err := http.NewRequest(http.MethodPost, "/user/info", strings.NewReader(formData.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			require.Equal(t, tt.expectedStatus, rec.Code)
			require.Equal(t, tt.expectedBody, rec.Body.String())
		})
	}
}
