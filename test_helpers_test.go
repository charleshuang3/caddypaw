package caddypaw

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/charleshuang3/caddypaw/internal/testdata"
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
