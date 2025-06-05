package caddypaw

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"bitbucket.org/creachadair/stringset"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/charleshuang3/caddypaw/internal/config"
	"github.com/charleshuang3/caddypaw/internal/testdata"
)

func validUser() *userInfo {
	return &userInfo{
		Username: "testuser",
		Name:     "Test User",
		Roles:    "admin user",
		Email:    "test@example.com",
		Picture:  "http://example.com/pic.jpg",
		roles:    stringset.New("admin", "user"),
	}
}

func TestAuthModule_validateJWT_Success(t *testing.T) {
	authModule := &AuthModule{
		ClientID:  "test-client",
		publicKey: testdata.PublicKey,
		authnConfig: &config.AuthnConfig{
			Issuer: "test-issuer",
		},
		logger: zap.NewNop(), // Use a no-op logger for tests
	}

	u := validUser()

	token := genAccessToken(t, "test-issuer", time.Now().Add(time.Minute), "test-client", u)
	u, err := authModule.validateJWT(token)

	require.NoError(t, err)
	require.NotNil(t, u)
	assert.Equal(t, u.Username, u.Username)
	assert.Equal(t, u.Name, u.Name)
	assert.Equal(t, u.Roles, u.Roles)
	assert.Equal(t, u.Email, u.Email)
	assert.Equal(t, u.Picture, u.Picture)
	assert.True(t, u.roles.Contains("admin"))
	assert.True(t, u.roles.Contains("user"))
}

func TestAuthModule_validateJWT_Error(t *testing.T) {
	authModule := &AuthModule{
		ClientID:  "test-client-id",
		publicKey: testdata.PublicKey,
		authnConfig: &config.AuthnConfig{
			Issuer: "test-issuer",
		},
		logger: zap.NewNop(), // Use a no-op logger for tests
	}

	type testCase struct {
		name        string
		issuer      string
		expiration  time.Duration
		clientID    string
		user        *userInfo
		modifyToken func(string) string // Optional: function to modify the token after generation
		assertErr   func(t *testing.T, err error)
	}

	tests := []testCase{
		{
			name:       "Expired Token",
			issuer:     authModule.authnConfig.Issuer,
			expiration: -time.Hour,
			clientID:   "test-client-id",
			user:       validUser(),
			assertErr: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, jwt.TokenExpiredError()))
			},
		},
		{
			name:       "Invalid Issuer",
			issuer:     "invalid-issuer",
			expiration: time.Hour,
			clientID:   "test-client-id",
			user:       validUser(),
			assertErr: func(t *testing.T, err error) {
				assert.EqualError(t, err, "invalid issuer")
			},
		},
		{
			name:       "No Subject",
			issuer:     authModule.authnConfig.Issuer,
			expiration: time.Hour,
			clientID:   "test-client-id",
			user:       func() *userInfo { u := validUser(); u.Username = ""; return u }(),
			assertErr: func(t *testing.T, err error) {
				assert.EqualError(t, err, "no subject in token")
			},
		},
		{
			name:       "Missing Name Claim",
			issuer:     authModule.authnConfig.Issuer,
			expiration: time.Hour,
			clientID:   "test-client-id",
			user:       func() *userInfo { u := validUser(); u.Name = ""; return u }(),
			assertErr: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, `field "name" not found`)
			},
		},
		{
			name:       "Missing Roles Claim",
			issuer:     authModule.authnConfig.Issuer,
			expiration: time.Hour,
			clientID:   "test-client-id",
			user:       func() *userInfo { u := validUser(); u.Roles = ""; return u }(),
			assertErr: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, `field "roles" not found`)
			},
		},
		{
			name:       "Missing Email Claim",
			issuer:     authModule.authnConfig.Issuer,
			expiration: time.Hour,
			clientID:   "test-client-id",
			user:       func() *userInfo { u := validUser(); u.Email = ""; return u }(),
			assertErr: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, `field "email" not found`)
			},
		},
		{
			name:       "Missing Picture Claim",
			issuer:     authModule.authnConfig.Issuer,
			expiration: time.Hour,
			clientID:   "test-client-id",
			user:       func() *userInfo { u := validUser(); u.Picture = ""; return u }(),
			assertErr: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, `field "picture" not found`)
			},
		},
		{
			name:       "Invalid Audience",
			issuer:     authModule.authnConfig.Issuer,
			expiration: time.Hour,
			clientID:   "invalid-client",
			user:       validUser(),
			assertErr: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, "invalid audience")
			},
		},
		{
			name:       "No Audience",
			issuer:     authModule.authnConfig.Issuer,
			expiration: time.Hour,
			clientID:   "",
			user:       validUser(),
			assertErr: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, "no audience")
			},
		},
		{
			name:        "Invalid Signature",
			issuer:      authModule.authnConfig.Issuer,
			expiration:  time.Hour,
			clientID:    "test-client-id",
			user:        validUser(),
			modifyToken: func(token string) string { return token + "invalid-signature" },
			assertErr: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, "verification error")
			},
		},
	}

	for _, tc := range tests {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			token := genAccessToken(t, tc.issuer, time.Now().Add(tc.expiration), tc.clientID, tc.user)
			if tc.modifyToken != nil {
				token = tc.modifyToken(token)
			}

			_, err := authModule.validateJWT(token)

			require.Error(t, err)
			tc.assertErr(t, err)
		})
	}
}

func TestCheckServerCookies_redirectToAuthorize(t *testing.T) {
	_, testServer := setupMockAuthnServer(t)
	a := newAuthModule(t, testServer, authTypeServerCookies)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	code, user, err := a.checkServerCookies(w, r)

	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, code)
	assert.Nil(t, user)

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	require.NotEmpty(t, location)
	assert.Equal(t, a.authnConfig.AuthURL, strings.Split(location, "?")[0])

	urlLocation, err := url.Parse(location)
	require.NoError(t, err)

	q := urlLocation.Query()
	assert.Equal(t, a.oauth2Config.RedirectURL, q.Get("redirect_uri"))
	assert.Equal(t, a.ClientID, q.Get("client_id"))

	state := q.Get("state")
	assert.NotEmpty(t, state)

	a.stateCache.Wait()
	storedURL, ok := a.getState(state)
	require.True(t, ok)
	assert.Equal(t, "/", storedURL)
}

func TestCheckServerCookies_handleDefaultCallback(t *testing.T) {
	mockServer, testServer := setupMockAuthnServer(t)
	a := newAuthModule(t, testServer, authTypeServerCookies)

	mockServer.user = validUser()
	mockServer.responseCode = http.StatusOK
	originalURL := "http://example.com/path?q=v"
	st := a.storeURLAndGenState(originalURL)
	a.stateCache.Wait()

	w := httptest.NewRecorder()

	q := url.Values{}
	q.Set("code", "test-code")
	q.Set("state", st)

	_url := defaultCallbackURL + "?" + q.Encode()
	r := httptest.NewRequest(http.MethodGet, _url, nil)

	code, user, err := a.checkServerCookies(w, r)
	require.NoError(t, err)
	assert.Nil(t, user)
	assert.Equal(t, http.StatusFound, code)
	assert.Equal(t, originalURL, w.Header().Get("Location"))

	assert.Len(t, mockServer.tokenRequests, 1)

	// state should be deleted
	a.stateCache.Wait()
	_, ok := a.getState(st)
	assert.False(t, ok)

	// cookies is set
	cookies := w.Result().Cookies()
	m := make(map[string]string)
	for _, c := range cookies {
		m[c.Name] = c.Value
	}

	assert.NotEmpty(t, m[cookieKeyAccessToken])
	assert.NotEmpty(t, m[cookieKeyRefreshToken])
}

func TestCheckServerCookies_handleDefaultCallback_Error(t *testing.T) {
	mockServer, testServer := setupMockAuthnServer(t)
	a := newAuthModule(t, testServer, authTypeServerCookies)

	type testCase struct {
		name           string
		code           string
		state          string
		mockServerCode int
		setup          func() // setup for test case
		assertCode     int
		assertErr      string
	}

	tests := []testCase{
		{
			name:       "No Code",
			code:       "",
			state:      "some-state",
			assertCode: http.StatusBadRequest,
			assertErr:  "no code",
		},
		{
			name:       "No State",
			code:       "some-code",
			state:      "",
			assertCode: http.StatusBadRequest,
			assertErr:  "no state",
		},
		{
			name:       "Invalid State",
			code:       "some-code",
			state:      "invalid-state",
			assertCode: http.StatusBadRequest,
			assertErr:  "invalid state",
		},
		{
			name:           "Mock Server 401",
			code:           "some-code",
			state:          a.storeURLAndGenState("http://example.com"),
			mockServerCode: http.StatusUnauthorized,
			setup: func() {
				mockServer.responseCode = http.StatusUnauthorized
			},
			assertCode: http.StatusUnauthorized,
			assertErr:  "oauth2: cannot fetch token: 401 Unauthorized\nResponse: ",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup()
			}

			w := httptest.NewRecorder()
			q := url.Values{}
			q.Set("code", tc.code)
			q.Set("state", tc.state)
			_url := defaultCallbackURL + "?" + q.Encode()
			r := httptest.NewRequest(http.MethodGet, _url, nil)

			a.stateCache.Wait()
			code, user, err := a.checkServerCookies(w, r)

			assert.Equal(t, tc.assertCode, code)
			assert.Nil(t, user)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.assertErr)
		})
	}
}
