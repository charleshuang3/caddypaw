package caddypaw

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"bitbucket.org/creachadair/stringset"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/dgraph-io/ristretto/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/charleshuang3/caddypaw/internal/config"
)

type mockAuthnServer struct {
	responseCode      int
	user              *userInfo
	basicAuthRequests []*http.Request
}

type mockCaddyHTTPHandler struct {
	handler func(http.ResponseWriter, *http.Request) error
}

func (m *mockCaddyHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	return m.handler(w, r)
}

func (s *mockAuthnServer) basicAuth(w http.ResponseWriter, r *http.Request) {
	s.basicAuthRequests = append(s.basicAuthRequests, r)

	if s.responseCode != http.StatusOK {
		w.WriteHeader(s.responseCode)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.user)
}

func setupMockAuthnServer(t *testing.T) (*mockAuthnServer, *httptest.Server) {
	t.Helper()

	mock := &mockAuthnServer{}

	mux := http.NewServeMux()
	mux.HandleFunc("/user/info", mock.basicAuth)

	testServer := httptest.NewServer(mux)
	httpClient = testServer.Client()

	t.Cleanup(func() {
		httpClient = http.DefaultClient
		testServer.Close()
	})

	return mock, testServer
}

func newAuthModule(t *testing.T, testServer *httptest.Server, ty authType) *AuthModule {
	cache, err := ristretto.NewCache(&ristretto.Config[string, *basicAuth]{
		NumCounters: 1e7,
		MaxCost:     1e7,
		BufferItems: 16,
	})
	require.NoError(t, err)

	a := &AuthModule{
		AuthType:     ty,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Roles:        []string{"admin", "user"},
		authnConfig: &config.AuthnConfig{
			NonOIDCUserInfoURL: testServer.URL + "/user/info",
		},
		basicAuthCache: cache,
		logger:         zap.L(),
	}

	return a
}

func TestCheckBasicAuth(t *testing.T) {
	mock, testServer := setupMockAuthnServer(t)
	a := newAuthModule(t, testServer, authTypeBasicAuth)

	mock.responseCode = http.StatusOK
	want := &userInfo{
		Username:   "test-user",
		Roles:      "admin webdav",
		Expiration: time.Now().Add(time.Hour).Unix(),
	}
	mock.user = want

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.SetBasicAuth("test-user", "test-password")

	ok, user, err := a.checkBasicAuth(w, r)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, want.Username, user.Username)
	assert.Equal(t, want.Roles, user.Roles)
	assert.Equal(t, stringset.New("admin", "webdav"), user.roles)

	assert.Len(t, mock.basicAuthRequests, 1)

	a.basicAuthCache.Wait()
	o, ok := a.getBasicAuth("test-user")
	require.True(t, ok)
	assert.Equal(t, "test-password", o.password)
	assert.Equal(t, user, o.user)
}

func TestCheckBasicAuth_NoBasicAuthHeader(t *testing.T) {
	mock, testServer := setupMockAuthnServer(t)
	a := newAuthModule(t, testServer, authTypeBasicAuth)

	mock.responseCode = http.StatusOK
	mock.user = &userInfo{
		Username:   "test-user",
		Roles:      "admin webdav",
		Expiration: time.Now().Add(time.Hour).Unix(),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	ok, user, err := a.checkBasicAuth(w, r)
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, user)
	assert.NotEmpty(t, w.Header().Get("WWW-Authenticate"))

	assert.Len(t, mock.basicAuthRequests, 0)
	a.basicAuthCache.Wait()
	_, ok = a.getBasicAuth("test-user")
	assert.False(t, ok)
}

func TestCheckBasicAuth_AuthnServerResponseError(t *testing.T) {
	tests := []struct {
		name         string
		responseCode int
		wantErr      bool
		wantHeader   string
	}{
		{
			name:         "authn server response 401",
			responseCode: http.StatusUnauthorized,
			wantErr:      false,
			wantHeader:   "WWW-Authenticate",
		},
		{
			name:         "authn server response 500",
			responseCode: http.StatusInternalServerError,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		mock, testServer := setupMockAuthnServer(t)
		a := newAuthModule(t, testServer, authTypeBasicAuth)

		mock.responseCode = tt.responseCode

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.SetBasicAuth("test-user", "test-password")

		ok, user, err := a.checkBasicAuth(w, r)
		assert.False(t, ok)
		assert.Nil(t, user)
		if tt.wantErr {
			assert.NotNil(t, err)
		} else {
			assert.NoError(t, err)
		}

		if tt.wantHeader != "" {
			assert.NotEmpty(t, w.Header().Get(tt.wantHeader))
		}

		assert.Len(t, mock.basicAuthRequests, 1)
		a.basicAuthCache.Wait()
		_, ok = a.getBasicAuth("test-user")
		assert.False(t, ok)
	}
}

func TestCheckBasicAuth_Cache(t *testing.T) {
	expiration := time.Now().Add(time.Hour).Unix()

	tests := []struct {
		name     string
		password string
		wantNext bool
		wantUser *userInfo
	}{
		{
			name:     "password match",
			password: "test-password",
			wantNext: true,
			wantUser: &userInfo{
				Username:   "test-user",
				Roles:      "admin webdav",
				roles:      stringset.New("admin", "webdav"),
				Expiration: expiration,
			},
		},
		{
			name:     "password does not match",
			password: "wrong-password",
			wantNext: false,
			wantUser: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, testServer := setupMockAuthnServer(t)
			a := newAuthModule(t, testServer, authTypeBasicAuth)

			// preload cache
			a.storeBasicAuth("test-user", "test-password", &userInfo{
				Username:   "test-user",
				Roles:      "admin webdav",
				roles:      stringset.New("admin", "webdav"),
				Expiration: expiration,
			})

			a.basicAuthCache.Wait()

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.SetBasicAuth("test-user", tt.password)

			ok, user, err := a.checkBasicAuth(w, r)
			require.NoError(t, err)
			assert.Equal(t, tt.wantNext, ok)
			assert.Equal(t, tt.wantUser, user)
			assert.Len(t, mock.basicAuthRequests, 0)
		})
	}
}

func TestServeHTTP_BasicAuth(t *testing.T) {
	mock, testServer := setupMockAuthnServer(t)
	a := newAuthModule(t, testServer, authTypeBasicAuth)
	a.Roles = []string{"admin"} // Set required role for this test

	mock.responseCode = http.StatusOK
	mock.user = &userInfo{
		Username:   "test-user",
		Roles:      "admin", // User has the required role
		Expiration: time.Now().Add(time.Hour).Unix(),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.SetBasicAuth("test-user", "test-password")

	// Mock the next handler in the chain
	nextHandler := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	}}

	err := a.ServeHTTP(w, r, nextHandler)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestServeHTTP_BasicAuth_Error(t *testing.T) {
	tests := []struct {
		name            string
		setupAuthModule func(*testing.T, *httptest.Server) *AuthModule
		setupRequest    func(*http.Request)
		mockResponse    func(*mockAuthnServer)
		wantStatusCode  int
	}{
		{
			name: "checkBasicAuth returns promptForCredentials (no basic auth header)",
			setupAuthModule: func(t *testing.T, ts *httptest.Server) *AuthModule {
				a := newAuthModule(t, ts, authTypeBasicAuth)
				a.Roles = []string{"admin"}
				return a
			},
			setupRequest: func(r *http.Request) {
				// No basic auth header
			},
			mockResponse: func(mock *mockAuthnServer) {
				mock.responseCode = http.StatusOK // This won't be hit as checkBasicAuth returns early
			},
			wantStatusCode: http.StatusUnauthorized,
		},
		{
			name: "checkBasicAuth returns promptForCredentials (wrong password)",
			setupAuthModule: func(t *testing.T, ts *httptest.Server) *AuthModule {
				a := newAuthModule(t, ts, authTypeBasicAuth)
				a.Roles = []string{"admin"}
				return a
			},
			setupRequest: func(r *http.Request) {
				r.SetBasicAuth("test-user", "wrong-password")
			},
			mockResponse: func(mock *mockAuthnServer) {
				mock.responseCode = http.StatusUnauthorized // Simulate authn server returning 401
			},
			wantStatusCode: http.StatusUnauthorized,
		},
		{
			name: "checkBasicAuth returns error (authn server internal error)",
			setupAuthModule: func(t *testing.T, ts *httptest.Server) *AuthModule {
				a := newAuthModule(t, ts, authTypeBasicAuth)
				a.Roles = []string{"admin"}
				return a
			},
			setupRequest: func(r *http.Request) {
				r.SetBasicAuth("test-user", "test-password")
			},
			mockResponse: func(mock *mockAuthnServer) {
				mock.responseCode = http.StatusInternalServerError // Simulate authn server returning 500
			},
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name: "checkBasicAuth returns user, but role does not match",
			setupAuthModule: func(t *testing.T, ts *httptest.Server) *AuthModule {
				a := newAuthModule(t, ts, authTypeBasicAuth)
				a.Roles = []string{"admin"} // Required role is admin
				return a
			},
			setupRequest: func(r *http.Request) {
				r.SetBasicAuth("test-user", "test-password")
			},
			mockResponse: func(mock *mockAuthnServer) {
				mock.responseCode = http.StatusOK
				mock.user = &userInfo{
					Username:   "test-user",
					Roles:      "user", // User has 'user' role, not 'admin'
					Expiration: time.Now().Add(time.Hour).Unix(),
				}
			},
			wantStatusCode: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, testServer := setupMockAuthnServer(t)
			a := tt.setupAuthModule(t, testServer)
			tt.mockResponse(mock)

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			tt.setupRequest(r)

			// Mock the next handler in the chain
			called := false
			nextHandler := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
				w.WriteHeader(http.StatusOK)
				called = true
				return nil
			}}

			err := a.ServeHTTP(w, r, nextHandler)
			assert.Error(t, err) // Expect an error for all these cases
			assert.IsType(t, caddyhttp.HandlerError{}, err)
			assert.Equal(t, tt.wantStatusCode, err.(caddyhttp.HandlerError).StatusCode)
			assert.False(t, called)
		})
	}
}
