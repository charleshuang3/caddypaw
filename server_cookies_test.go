package caddypaw

import (
	"errors"
	"testing"
	"time"

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
		ClientID:  "test-client",
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
			clientID:   "test-client",
			user:       validUser(),
			assertErr: func(t *testing.T, err error) {
				assert.True(t, errors.Is(err, jwt.TokenExpiredError()))
			},
		},
		{
			name:       "Invalid Issuer",
			issuer:     "invalid-issuer",
			expiration: time.Hour,
			clientID:   "test-client",
			user:       validUser(),
			assertErr: func(t *testing.T, err error) {
				assert.EqualError(t, err, "invalid issuer")
			},
		},
		{
			name:       "No Subject",
			issuer:     authModule.authnConfig.Issuer,
			expiration: time.Hour,
			clientID:   "test-client",
			user:       func() *userInfo { u := validUser(); u.Username = ""; return u }(),
			assertErr: func(t *testing.T, err error) {
				assert.EqualError(t, err, "no subject in token")
			},
		},
		{
			name:       "Missing Name Claim",
			issuer:     authModule.authnConfig.Issuer,
			expiration: time.Hour,
			clientID:   "test-client",
			user:       func() *userInfo { u := validUser(); u.Name = ""; return u }(),
			assertErr: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, `field "name" not found`)
			},
		},
		{
			name:       "Missing Roles Claim",
			issuer:     authModule.authnConfig.Issuer,
			expiration: time.Hour,
			clientID:   "test-client",
			user:       func() *userInfo { u := validUser(); u.Roles = ""; return u }(),
			assertErr: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, `field "roles" not found`)
			},
		},
		{
			name:       "Missing Email Claim",
			issuer:     authModule.authnConfig.Issuer,
			expiration: time.Hour,
			clientID:   "test-client",
			user:       func() *userInfo { u := validUser(); u.Email = ""; return u }(),
			assertErr: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, `field "email" not found`)
			},
		},
		{
			name:       "Missing Picture Claim",
			issuer:     authModule.authnConfig.Issuer,
			expiration: time.Hour,
			clientID:   "test-client",
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
			clientID:    "test-client",
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
