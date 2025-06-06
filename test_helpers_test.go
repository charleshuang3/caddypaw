package caddypaw

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"github.com/charleshuang3/caddypaw/internal/config"
	"github.com/charleshuang3/caddypaw/internal/testdata"
)

type mockAuthnServer struct {
	t *testing.T

	responseCode      int
	user              *userInfo
	basicAuthRequests []*http.Request
	tokenRequests     []*http.Request
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

func (s *mockAuthnServer) token(w http.ResponseWriter, r *http.Request) {
	s.t.Helper()

	s.tokenRequests = append(s.tokenRequests, r)

	if s.responseCode != http.StatusOK {
		w.WriteHeader(s.responseCode)
		return
	}

	token := genAccessToken(s.t, "test-issuer", time.Now().Add(time.Hour), "test-client-id", s.user)

	tokenResp := struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}{
		IDToken:      token,
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tokenResp)
}

func setupMockAuthnServer(t *testing.T) (*mockAuthnServer, *httptest.Server) {
	t.Helper()

	mock := &mockAuthnServer{
		t: t,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/user/info", mock.basicAuth)
	mux.HandleFunc("/oauth2/token", mock.token)

	testServer := httptest.NewServer(mux)
	httpClient = testServer.Client()

	t.Cleanup(func() {
		httpClient = http.DefaultClient
		testServer.Close()
	})

	return mock, testServer
}

func genAccessToken(t *testing.T, iss string, exp time.Time, clientID string, user *userInfo) string {
	t.Helper()

	b := jwt.NewBuilder()
	if iss != "" {
		b.Issuer(iss)
	}
	b.IssuedAt(time.Now())
	b.Expiration(exp)
	if clientID != "" {
		b.Audience([]string{clientID})
	}
	if user.Username != "" {
		b.Subject(user.Username)
	}
	if user.Name != "" {
		b.Claim("name", user.Name)
	}
	if user.Roles != "" {
		b.Claim("roles", user.Roles)
	}
	if user.Email != "" {
		b.Claim("email", user.Email)
	}
	if user.Picture != "" {
		b.Claim("picture", user.Picture)
	}
	b.Claim("scope", "openid profile email")

	token, err := b.Build()
	require.NoError(t, err)

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), testdata.PrivateKey))
	require.NoError(t, err)

	return string(signed)
}

func newAuthModule(t *testing.T, testServer *httptest.Server, ty authType) *authModule {
	baCache, err := ristretto.NewCache(&ristretto.Config[string, *basicAuth]{
		NumCounters: 1e7,
		MaxCost:     1e7,
		BufferItems: 16,
	})
	require.NoError(t, err)

	stateCache, err := ristretto.NewCache(&ristretto.Config[string, string]{
		NumCounters: 1e7,
		MaxCost:     1e7,
		BufferItems: 16,
	})
	require.NoError(t, err)

	a := &authModule{
		AuthType:     ty,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Roles:        []string{"admin", "user"},
		authnConfig: &config.AuthnConfig{
			NonOIDCUserInfoURL: testServer.URL + "/user/info",
			Issuer:             "test-issuer",
			AuthURL:            testServer.URL + "/oauth2/authorize",
			TokenURL:           testServer.URL + "/oauth2/token",
		},
		oauth2Config: &oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			Endpoint: oauth2.Endpoint{
				TokenURL: testServer.URL + "/oauth2/token",
				AuthURL:  testServer.URL + "/oauth2/authorize",
			},
			RedirectURL: "http://localhost/paw/callback",
			Scopes:      []string{"openid", "profile", "email", "offline_access"},
		},
		basicAuthCache: baCache,
		stateCache:     stateCache,
		publicKey:      testdata.PublicKey,
		logger:         zap.NewNop(),
	}

	return a
}
