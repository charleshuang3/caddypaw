package caddypaw

import (
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
		expected    *Auth
		expectError bool
	}{
		{
			name: "valid configuration",
			caddyfile: `paw_auth {
				client_id the-client-id
				client_secret the-client-secret
				roles role1 role2
			}`,
			expected: &Auth{
				ClientID:     "the-client-id",
				ClientSecret: "the-client-secret",
				Roles:        []string{"role1", "role2"},
			},
			expectError: false,
		},
		{
			name: "valid configuration with optional fields",
			caddyfile: `paw_auth {
				client_id the-client-id
				client_secret the-client-secret
				roles role1 role2
				callback_url https://example.com/callback
				public_urls path_prefix:/path1 path_prefix:/path2
			}`,
			expected: &Auth{
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
				client_secret the-client-secret
				roles role1
			}`,
			expected: &Auth{
				ClientSecret: "the-client-secret",
				Roles:        []string{"role1"},
			},
			expectError: false,
		},
		{
			name: "missing client_secret",
			caddyfile: `paw_auth {
				client_id the-client-id
				roles role1
			}`,
			expected: &Auth{
				ClientID: "the-client-id",
				Roles:    []string{"role1"},
			},
			expectError: false,
		},
		{
			name: "missing roles",
			caddyfile: `paw_auth {
				client_id the-client-id
				client_secret the-client-secret
			}`,
			expected: &Auth{
				ClientID:     "the-client-id",
				ClientSecret: "the-client-secret",
			},
			expectError: false,
		},
		{
			name: "empty roles",
			caddyfile: `paw_auth {
				client_id the-client-id
				client_secret the-client-secret
				roles
			}`,
			expectError: true,
		},
		{
			name: "unrecognized subdirective",
			caddyfile: `paw_auth {
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
				client_id the-client-id
				client_secret the-client-secret
				roles role1
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.caddyfile)
			p := &Auth{}
			err := p.UnmarshalCaddyfile(d)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.ClientID, p.ClientID)
				assert.Equal(t, tt.expected.ClientSecret, p.ClientSecret)
				assert.Equal(t, tt.expected.Roles, p.Roles)
				assert.Equal(t, tt.expected.CallbackURL, p.CallbackURL)
				assert.Equal(t, tt.expected.PublicURLs, p.PublicURLs)
			}
		})
	}
}

func TestAuthValidate(t *testing.T) {
	tests := []struct {
		name        string
		auth        Auth
		expectError bool
	}{
		{
			name: "valid configuration",
			auth: Auth{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				Roles:        []string{"admin", "user"},
			},
			expectError: false,
		},
		{
			name: "missing client_id",
			auth: Auth{
				ClientSecret: "test-client-secret",
				Roles:        []string{"admin"},
			},
			expectError: true,
		},
		{
			name: "missing client_secret",
			auth: Auth{
				ClientID: "test-client-id",
				Roles:    []string{"admin"},
			},
			expectError: true,
		},
		{
			name: "missing roles",
			auth: Auth{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
			expectError: true,
		},
		{
			name: "empty roles slice",
			auth: Auth{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				Roles:        []string{},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.auth.Validate()
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

	a := &Auth{}

	err = a.Provision(ctx)
	require.NoError(t, err)

	assert.Equal(t,
		&config.AuthnConfig{
			AuthURL:      "https://example.com:8443/oauth2/authorize",
			TokenURL:     "https://example.com:8443/oauth2/token",
			FirewallURL:  "http://127.0.0.1:8444/",
			PublicKeyPEM: testdata.PublicKeyPEM,
		}, a.authnConfig)

	assert.NotNil(t, a.publicKey)
}
