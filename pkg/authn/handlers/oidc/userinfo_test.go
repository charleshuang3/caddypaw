package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/charleshuang3/caddypaw/pkg/authn/models"
)

func setupTestForUserInfo(t *testing.T) (*OpenIDProvider, *gin.Engine) {
	t.Helper()

	provider, db, router := setupTestProviderForTokenRequest(t)

	err := db.Model(&models.User{}).Where("username = ?", "existinguser").Updates(map[string]any{
		"Name":    "Existing User",
		"Email":   "existing@example.com",
		"Picture": "https://example.com/picture.jpg",
		"Roles":   "user admin",
	}).Error
	require.NoError(t, err)

	return provider, router
}

func genTestAccessToken(t *testing.T, p *OpenIDProvider, subject string, scopes []string, expires time.Time) string {
	t.Helper()

	b := jwt.NewBuilder().
		Issuer(p.config.Issuer).
		IssuedAt(time.Now()).
		Expiration(expires).
		Audience([]string{"existing-client"}).
		Subject(subject)
	if len(scopes) > 0 {
		b = b.Claim("scope", joinScopes(scopes))
	}
	token, err := b.Build()
	require.NoError(t, err)

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), p.privateKey))
	require.NoError(t, err)
	return string(signed)
}

func joinScopes(scopes []string) string {
	out := ""
	for i, s := range scopes {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}

func TestHandleUserInfo(t *testing.T) {
	tests := []struct {
		name           string
		subject        string
		scopes         []string
		expectedStatus int
		checkClaims    func(*testing.T, userInfoResponse)
	}{
		{
			name:           "profile and email scopes",
			subject:        "existinguser",
			scopes:         []string{"openid", "profile", "email"},
			expectedStatus: http.StatusOK,
			checkClaims: func(t *testing.T, r userInfoResponse) {
				assert.Equal(t, "existinguser", r.Sub)
				assert.Equal(t, "Existing User", r.Name)
				assert.Equal(t, "https://example.com/picture.jpg", r.Picture)
				assert.Equal(t, "user admin", r.Roles)
				assert.Equal(t, "existing@example.com", r.Email)
			},
		},
		{
			name:           "email scope only",
			subject:        "existinguser",
			scopes:         []string{"openid", "email"},
			expectedStatus: http.StatusOK,
			checkClaims: func(t *testing.T, r userInfoResponse) {
				assert.Equal(t, "existinguser", r.Sub)
				assert.Empty(t, r.Name, "profile claims must be omitted without profile scope")
				assert.Empty(t, r.Picture)
				assert.Empty(t, r.Roles)
				assert.Equal(t, "existing@example.com", r.Email)
			},
		},
		{
			name:           "no scopes",
			subject:        "existinguser",
			scopes:         nil,
			expectedStatus: http.StatusOK,
			checkClaims: func(t *testing.T, r userInfoResponse) {
				assert.Equal(t, "existinguser", r.Sub)
				assert.Empty(t, r.Name)
				assert.Empty(t, r.Email)
			},
		},
		{
			name:           "unknown subject",
			subject:        "nonexistent",
			scopes:         []string{"openid"},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, router := setupTestForUserInfo(t)

			token := genTestAccessToken(t, provider, tt.subject, tt.scopes, time.Now().Add(time.Minute))

			req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code, "Body: %s", rec.Body.String())

			if tt.checkClaims != nil {
				var resp userInfoResponse
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
				tt.checkClaims(t, resp)
			}
		})
	}
}

func TestHandleUserInfo_BadToken(t *testing.T) {
	provider, router := setupTestForUserInfo(t)

	tests := []struct {
		name  string
		token func() string
	}{
		{
			name:  "no Authorization header",
			token: func() string { return "" },
		},
		{
			name:  "garbage token",
			token: func() string { return "not-a-jwt" },
		},
		{
			name: "expired token",
			token: func() string {
				return genTestAccessToken(t, provider, "existinguser", []string{"openid"}, time.Now().Add(-time.Minute))
			},
		},
		{
			name: "wrong issuer",
			token: func() string {
				token, err := jwt.NewBuilder().
					Issuer("https://evil.example").
					IssuedAt(time.Now()).
					Expiration(time.Now().Add(time.Minute)).
					Subject("existinguser").
					Build()
				require.NoError(t, err)
				signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), provider.privateKey))
				require.NoError(t, err)
				return string(signed)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
			if tok := tt.token(); tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusUnauthorized, rec.Code)
		})
	}
}
