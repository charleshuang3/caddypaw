package caddypaw

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"bitbucket.org/creachadair/stringset"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/charleshuang3/caddypaw/pkg/waf"
)

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

	status, user, err := a.checkBasicAuth(w, r, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, want.Username, user.Username)
	assert.Equal(t, want.Roles, user.Roles)
	assert.Equal(t, stringset.New("admin", "webdav"), user.roles)

	assert.Len(t, mock.basicAuthRequests, 1)

	a.basicAuthCache.Wait()
	o, cacheOk := a.getBasicAuth("test-user")
	require.True(t, cacheOk)
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

	status, user, err := a.checkBasicAuth(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Nil(t, user)
	assert.NotEmpty(t, w.Header().Get("WWW-Authenticate"))

	assert.Len(t, mock.basicAuthRequests, 0)
	a.basicAuthCache.Wait()
	_, cacheOk := a.getBasicAuth("test-user")
	assert.False(t, cacheOk)
}

func TestCheckBasicAuth_AuthnServerResponseError(t *testing.T) {
	tests := []struct {
		name         string
		responseCode int
		wantErr      bool
		wantHeader   string
		wantStatus   int // New field for expected status
	}{
		{
			name:         "authn server response 401",
			responseCode: http.StatusUnauthorized,
			wantErr:      false,
			wantHeader:   "WWW-Authenticate",
			wantStatus:   http.StatusUnauthorized,
		},
		{
			name:         "authn server response 500",
			responseCode: http.StatusInternalServerError,
			wantErr:      true,
			wantStatus:   http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		mock, testServer := setupMockAuthnServer(t)
		a := newAuthModule(t, testServer, authTypeBasicAuth)

		mock.responseCode = tt.responseCode

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.SetBasicAuth("test-user", "test-password")

		status, user, err := a.checkBasicAuth(w, r, nil)
		assert.Equal(t, tt.wantStatus, status) // Assert on the returned status
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
		_, cacheOk := a.getBasicAuth("test-user")
		assert.False(t, cacheOk)
	}
}

func TestCheckBasicAuth_Cache(t *testing.T) {
	expiration := time.Now().Add(time.Hour).Unix()

	tests := []struct {
		name       string
		password   string
		wantStatus int // Changed from wantNext to wantStatus
		wantUser   *userInfo
	}{
		{
			name:       "password match",
			password:   "test-password",
			wantStatus: http.StatusOK,
			wantUser: &userInfo{
				Username:   "test-user",
				Roles:      "admin webdav",
				roles:      stringset.New("admin", "webdav"),
				Expiration: expiration,
			},
		},
		{
			name:       "password does not match",
			password:   "wrong-password",
			wantStatus: http.StatusUnauthorized,
			wantUser:   nil,
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

			status, user, err := a.checkBasicAuth(w, r, nil)
			require.NoError(t, err)
			assert.Equal(t, tt.wantStatus, status)
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
		setupAuthModule func(*testing.T, *httptest.Server) *authModule
		setupRequest    func(*http.Request)
		mockResponse    func(*mockAuthnServer)
		wantStatusCode  int
	}{
		{
			name: "checkBasicAuth returns promptForCredentials (no basic auth header)",
			setupAuthModule: func(t *testing.T, ts *httptest.Server) *authModule {
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
			setupAuthModule: func(t *testing.T, ts *httptest.Server) *authModule {
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
			setupAuthModule: func(t *testing.T, ts *httptest.Server) *authModule {
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
			setupAuthModule: func(t *testing.T, ts *httptest.Server) *authModule {
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

func TestServeHTTP_BasicAuth_ReportsInvalidCredentials(t *testing.T) {
	tests := []struct {
		name          string
		username      string
		password      string
		setCredential bool
		cachePreload  bool
		// rawAuthHeader overrides the Authorization header verbatim.
		rawAuthHeader string
		// authnCode is what the mock authn server answers on a cache miss.
		authnCode  int
		wantReason string
		// wantNoReport suppresses every firewall assertion.
		wantNoReport bool
	}{
		{
			// A browser's first request carries no credentials at all. Nothing about
			// it says the client is attacking, so it must not be reported: counting
			// it would ban browsers, health checks and WebDAV clients for behaving
			// normally.
			name:          "missing credentials",
			setCredential: false,
			cachePreload:  false,
			wantNoReport:  true,
		},
		{
			name:          "malformed basic authorization header",
			setCredential: false,
			cachePreload:  false,
			rawAuthHeader: "Basic ###not-base64###",
			wantReason:    reasonInvalidCredentials,
		},
		{
			// Another scheme is not an attempt at basic auth, so it must not spend
			// the client's budget.
			name:          "foreign authorization scheme",
			setCredential: false,
			cachePreload:  false,
			rawAuthHeader: "Bearer some-token",
			wantNoReport:  true,
		},
		{
			name:          "cached user, wrong password",
			username:      "test-user",
			password:      "wrong-password",
			setCredential: true,
			cachePreload:  true,
			wantReason:    reasonInvalidCredentials,
		},
		{
			name:          "authn rejects credentials",
			username:      "test-user",
			password:      "wrong-password",
			setCredential: true,
			cachePreload:  false,
			authnCode:     http.StatusUnauthorized,
			wantReason:    reasonInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, testServer := setupMockAuthnServer(t)
			a := newAuthModule(t, testServer, authTypeBasicAuth)

			if tt.cachePreload {
				a.storeBasicAuth("test-user", "test-password", &userInfo{
					Username:   "test-user",
					Roles:      "admin",
					roles:      stringset.New("admin"),
					Expiration: time.Now().Add(time.Hour).Unix(),
				})
				a.basicAuthCache.Wait()
			}

			if tt.authnCode != 0 {
				mock.responseCode = tt.authnCode
			}

			nextCalled := false
			next := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
				return nil
			}}

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = "203.0.113.5:4321"
			if tt.setCredential {
				r.SetBasicAuth(tt.username, tt.password)
			}
			if tt.rawAuthHeader != "" {
				r.Header.Set("Authorization", tt.rawAuthHeader)
			}

			err := a.ServeHTTP(w, r, next)
			require.Error(t, err)
			assert.False(t, nextCalled)
			assert.Equal(t, `Basic realm="restricted"`, w.Header().Get("WWW-Authenticate"))

			if tt.wantNoReport {
				assert.Empty(t, mock.firewallRequests, "a request without credentials must not be reported")
				return
			}

			require.Len(t, mock.firewallRequests, 1, "a failed attempt must feed the ban pipeline")
			assert.Equal(t, "203.0.113.5", mock.firewallRequests[0].URL.Query().Get("ip"))
			assert.Equal(t, tt.wantReason, mock.firewallRequests[0].URL.Query().Get("reason"))
			assert.Empty(t, mock.firewallRequests[0].URL.Query().Get("weight"),
				"one signal is one point, so the parameter is omitted")
		})
	}
}

func TestServeHTTP_BasicAuth_SuccessIsNotReported(t *testing.T) {
	mock, testServer := setupMockAuthnServer(t)
	a := newAuthModule(t, testServer, authTypeBasicAuth)

	mock.responseCode = http.StatusOK
	mock.user = &userInfo{
		Username:   "test-user",
		Roles:      "admin",
		Expiration: time.Now().Add(time.Hour).Unix(),
	}

	next := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.6:4321"
	r.SetBasicAuth("test-user", "test-password")

	require.NoError(t, a.ServeHTTP(w, r, next))
	assert.Empty(t, mock.firewallRequests)
}

// TestServeHTTP_BasicAuth_WAFMatchWinsOverCredentialFailure verifies that a
// request failing both the WAF and authentication is reported exactly once, with
// both reasons and the sum of both weights: two independent signals are stronger
// evidence than either alone. Without credentials there is only one signal.
func TestServeHTTP_BasicAuth_WAFMatchWinsOverCredentialFailure(t *testing.T) {
	mock, a := newAfterAuthModule(t, waf.AfterAuthDetectOnly, afterAuthTestDirectives)

	next := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/attack", nil)
	r.RemoteAddr = "203.0.113.7:4321"
	r.SetBasicAuth("test-user", "wrong-password")

	require.Error(t, a.ServeHTTP(w, r, next))

	require.Len(t, mock.firewallRequests, 1, "one request must produce exactly one count")
	assert.Equal(t, "waf:6001 | "+reasonInvalidCredentials, mock.firewallRequests[0].URL.Query().Get("reason"))
	assert.Equal(t, "2", mock.firewallRequests[0].URL.Query().Get("weight"),
		"two corroborating signals weigh 1 + 1")

	// The same request without credentials must not be reported at all: no
	// credentials is a first visit, not a deliberate attempt.
	mock.firewallRequests = nil
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/attack", nil)
	r.RemoteAddr = "203.0.113.8:4321"

	require.Error(t, a.ServeHTTP(w, r, next))
	require.Len(t, mock.firewallRequests, 1,
		"without credentials only the WAF signal remains, and it is still reported")
	assert.Equal(t, "waf:6001", mock.firewallRequests[0].URL.Query().Get("reason"))
}
