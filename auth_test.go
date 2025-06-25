package caddypaw

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/charleshuang3/caddypaw/internal/config"
	"github.com/charleshuang3/caddypaw/internal/testdata"
)

func TestAuthUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name        string
		caddyfile   string
		expected    *authModule
		expectError bool
	}{
		{
			name: "valid configuration with basic_auth",
			caddyfile: `paw_auth {
				basic_auth
				client_id the-client-id
				client_secret the-client-secret
				roles role1 role2
			}`,
			expected: &authModule{
				AuthType:     authTypeBasicAuth,
				ClientID:     "the-client-id",
				ClientSecret: "the-client-secret",
				Roles:        []string{"role1", "role2"},
			},
			expectError: false,
		},
		{
			name: "valid configuration with server_cookies",
			caddyfile: `paw_auth {
				server_cookies
				client_id the-client-id
				client_secret the-client-secret
				roles role1 role2
			}`,
			expected: &authModule{
				AuthType:     authTypeServerCookies,
				ClientID:     "the-client-id",
				ClientSecret: "the-client-secret",
				Roles:        []string{"role1", "role2"},
			},
			expectError: false,
		},
		{
			name: "valid configuration with optional fields",
			caddyfile: `paw_auth {
				basic_auth
				client_id the-client-id
				client_secret the-client-secret
				roles role1 role2
				callback_url https://example.com/callback
				public_urls path_prefix:/path1 path_prefix:/path2
			}`,
			expected: &authModule{
				AuthType:     authTypeBasicAuth,
				ClientID:     "the-client-id",
				ClientSecret: "the-client-secret",
				Roles:        []string{"role1", "role2"},
				CallbackURL:  "https://example.com/callback",
				PublicURLs:   []*urlMatcher{{"path_prefix", "/path1"}, {"path_prefix", "/path2"}},
			},
			expectError: false,
		},
		{
			name: "missing client_id",
			caddyfile: `paw_auth {
				basic_auth
				client_secret the-client-secret
				roles role1
			}`,
			expected: &authModule{
				AuthType:     authTypeBasicAuth,
				ClientSecret: "the-client-secret",
				Roles:        []string{"role1"},
			},
			expectError: false,
		},
		{
			name: "missing client_secret",
			caddyfile: `paw_auth {
				basic_auth
				client_id the-client-id
				roles role1
			}`,
			expected: &authModule{
				AuthType: authTypeBasicAuth,
				ClientID: "the-client-id",
				Roles:    []string{"role1"},
			},
			expectError: false,
		},
		{
			name: "missing roles",
			caddyfile: `paw_auth {
				basic_auth
				client_id the-client-id
				client_secret the-client-secret
			}`,
			expected: &authModule{
				AuthType:     authTypeBasicAuth,
				ClientID:     "the-client-id",
				ClientSecret: "the-client-secret",
			},
			expectError: false,
		},
		{
			name: "empty roles",
			caddyfile: `paw_auth {
				basic_auth
				client_id the-client-id
				client_secret the-client-secret
				roles
			}`,
			expectError: true,
		},
		{
			name: "unrecognized subdirective",
			caddyfile: `paw_auth {
				basic_auth
				client_id the-client-id
				client_secret the-client-secret
				roles role1
				unknown_directive value
			}`,
			expectError: true,
		},
		{
			name: "no arguments after paw_auth directive",
			caddyfile: `paw_auth arg1 {
				basic_auth
				client_id the-client-id
				client_secret the-client-secret
				roles role1
			}`,
			expectError: true,
		},
		{
			name: "auth type set multiple times",
			caddyfile: `paw_auth {
				basic_auth
				server_cookies
				client_id the-client-id
				client_secret the-client-secret
				roles role1
			}`,
			expectError: true,
		},
		{
			name: "valid configuration with bearer_token",
			caddyfile: `paw_auth {
				bearer_token
				token test-token
				roles role1 role2
			}`,
			expected: &authModule{
				AuthType: authTypeBearerToken,
				Token:    "test-token",
				Roles:    []string{"role1", "role2"},
			},
			expectError: false,
		},
		{
			name: "missing token",
			caddyfile: `paw_auth {
				bearer_token
				roles role1 role2
			}`,
			expected: &authModule{
				AuthType: authTypeBearerToken,
				Roles:    []string{"role1", "role2"},
			},
			expectError: false,
		},
		{
			name: "bearer_token with other fields",
			caddyfile: `paw_auth {
				bearer_token
				token test-token
				roles role1 role2
				client_id client-id
				client_secret client-secret
			}`,
			expected: &authModule{
				AuthType:     authTypeBearerToken,
				Token:        "test-token",
				Roles:        []string{"role1", "role2"},
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.caddyfile)
			p := &authModule{}
			err := p.UnmarshalCaddyfile(d)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.AuthType, p.AuthType)
				assert.Equal(t, tt.expected.ClientID, p.ClientID)
				assert.Equal(t, tt.expected.ClientSecret, p.ClientSecret)
				assert.Equal(t, tt.expected.Roles, p.Roles)
				assert.Equal(t, tt.expected.CallbackURL, p.CallbackURL)
				assert.Equal(t, tt.expected.PublicURLs, p.PublicURLs)
				assert.Equal(t, tt.expected.Token, p.Token)
			}
		})
	}
}

func TestAuthConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		auth        authModule
		expectError bool
	}{
		{
			name: "valid configuration",
			auth: authModule{
				AuthType:     authTypeBasicAuth,
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				Roles:        []string{"admin", "user"},
				CallbackURL:  "https://example.com/callback",
			},
			expectError: false,
		},
		{
			name: "missing auth_type",
			auth: authModule{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				Roles:        []string{"admin", "user"},
			},
			expectError: true,
		},
		{
			name: "missing client_id",
			auth: authModule{
				AuthType:     authTypeBasicAuth,
				ClientSecret: "test-client-secret",
				Roles:        []string{"admin"},
			},
			expectError: true,
		},
		{
			name: "missing client_secret",
			auth: authModule{
				AuthType: authTypeBasicAuth,
				ClientID: "test-client-id",
				Roles:    []string{"admin"},
			},
			expectError: true,
		},
		{
			name: "missing roles",
			auth: authModule{
				AuthType:     authTypeBasicAuth,
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
			expectError: true,
		},
		{
			name: "empty roles slice",
			auth: authModule{
				AuthType:     authTypeBasicAuth,
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				Roles:        []string{},
			},
			expectError: true,
		},
		{
			name: "missing callback_url",
			auth: authModule{
				AuthType:     authTypeServerCookies,
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				Roles:        []string{"admin"},
			},
			expectError: true,
		},
		{
			name: "valid configuration with bearer token",
			auth: authModule{
				AuthType: authTypeBearerToken,
				Token:    "test-token",
				Roles:    []string{"admin"},
			},
			expectError: false,
		},
		{
			name: "missing token with bearer token",
			auth: authModule{
				AuthType: authTypeBearerToken,
				Roles:    []string{"admin"},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.auth.configValidate()
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAuthProvision(t *testing.T) {
	caddyfileInput := `{
	authn_yaml_file internal/testdata/test.yaml
}

example.com {
	respond "hi"
}
`

	cfg := caddyConfig(t, caddyfileInput)
	ctx, err := caddy.ProvisionContext(cfg)
	require.NoError(t, err)

	a := &authModule{
		AuthType:     authTypeBasicAuth,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Roles:        []string{"admin"},
		CallbackURL:  "https://example.com/callback",
	}

	err = a.Provision(ctx)
	require.NoError(t, err)

	assert.Equal(t,
		&config.AuthnConfig{
			Issuer:             "http://example.com:8443/oauth2",
			AuthURL:            "http://example.com:8443/oauth2/authorize",
			TokenURL:           "http://example.com:8443/oauth2/token",
			NonOIDCUserInfoURL: "http://example.com:8443/user/info",
			FirewallURL:        "http://127.0.0.1:8444/",
			PublicKeyPEM:       testdata.PublicKeyPEM,
		}, a.authnConfig)

	assert.NotNil(t, a.publicKey)
}

func TestAuthDirective(t *testing.T) {
	caddyfileInput := `{
	order paw_auth before basic_auth
	authn_yaml_file internal/testdata/test.yaml
}

example.com {
	paw_auth {
		basic_auth
		client_id the-client-id
		client_secret the-client-secret
		roles role1 role2
		callback_url https://example.com/callback
	}
	respond "hi"
}
`

	cfg := caddyConfig(t, caddyfileInput)

	// call ProvisionContext will provision and validate the config.
	_, err := caddy.ProvisionContext(cfg)
	assert.NoError(t, err)
}

func TestServeHTTP_PublicURLs(t *testing.T) {
	tt := []struct {
		name     string
		authType authType
	}{
		{
			name:     "basic_auth",
			authType: authTypeBasicAuth,
		},
		{
			name:     "server_cookies",
			authType: authTypeServerCookies,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			mock, testServer := setupMockAuthnServer(t)
			a := newAuthModule(t, testServer, tc.authType)

			var err error
			u, err := urlMatcherFromStr("path_prefix:/public")
			require.NoError(t, err)
			a.PublicURLs = append(a.PublicURLs, u)

			mock.responseCode = http.StatusUnauthorized

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/public", nil)

			// Mock the next handler in the chain
			nextHandler := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
				w.WriteHeader(http.StatusOK)
				return nil
			}}

			err = a.ServeHTTP(w, r, nextHandler)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}
