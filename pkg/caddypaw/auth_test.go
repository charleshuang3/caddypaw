package caddypaw

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bitbucket.org/creachadair/stringset"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/charleshuang3/caddypaw/pkg/caddypaw/config"
	"github.com/charleshuang3/caddypaw/pkg/caddypaw/testdata"
	"github.com/charleshuang3/caddypaw/pkg/waf"
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
		{
			name: "valid configuration with embedded waf followed by other subdirectives",
			caddyfile: `paw_auth {
				basic_auth
				waf {
					directives ` + "`SecRule REQUEST_URI \"@contains evil\" \"id:1001,phase:1,deny,status:403\"`" + `
				}
				client_id the-client-id
				client_secret the-client-secret
				roles role1 role2
				callback_url https://example.com/callback
				public_urls path_prefix:/path1
			}`,
			expected: &authModule{
				AuthType:     authTypeBasicAuth,
				ClientID:     "the-client-id",
				ClientSecret: "the-client-secret",
				Roles:        []string{"role1", "role2"},
				CallbackURL:  "https://example.com/callback",
				PublicURLs:   []*urlMatcher{{"path_prefix", "/path1"}},
				WAFConfig: &waf.Config{
					Directives: `SecRule REQUEST_URI "@contains evil" "id:1001,phase:1,deny,status:403"`,
				},
			},
			expectError: false,
		},
		{
			name: "valid configuration with embedded waf load_owasp_crs",
			caddyfile: `paw_auth {
				server_cookies
				client_id the-client-id
				client_secret the-client-secret
				roles role1
				callback_url https://example.com/callback
				waf {
					load_owasp_crs
					directives ` + "`SecRuleEngine On`" + `
				}
			}`,
			expected: &authModule{
				AuthType:     authTypeServerCookies,
				ClientID:     "the-client-id",
				ClientSecret: "the-client-secret",
				Roles:        []string{"role1"},
				CallbackURL:  "https://example.com/callback",
				WAFConfig: &waf.Config{
					LoadOWASPCRS: true,
					Directives:   "SecRuleEngine On",
				},
			},
			expectError: false,
		},
		{
			name: "valid configuration with embedded waf after_auth mode",
			caddyfile: `paw_auth {
				basic_auth
				client_id the-client-id
				client_secret the-client-secret
				roles role1
				waf {
					preset default
					after_auth detect_only
				}
			}`,
			expected: &authModule{
				AuthType:     authTypeBasicAuth,
				ClientID:     "the-client-id",
				ClientSecret: "the-client-secret",
				Roles:        []string{"role1"},
				WAFConfig: &waf.Config{
					Preset:    "default",
					AfterAuth: waf.AfterAuthDetectOnly,
				},
			},
			expectError: false,
		},
		{
			name: "duplicate waf block error",
			caddyfile: `paw_auth {
				basic_auth
				client_id the-client-id
				client_secret the-client-secret
				roles role1
				waf {
					directives ` + "`SecRuleEngine On`" + `
				}
				waf {
					directives ` + "`SecRuleEngine On`" + `
				}
			}`,
			expectError: true,
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
				assert.Equal(t, tt.expected.WAFConfig, p.WAFConfig)
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
	caddyfileInput := fmt.Sprintf(`{
	authn_yaml_file %s
}

example.com {
	respond "hi"
}
`, testdata.AuthnYAML(t))

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
			Issuer:             testdata.Issuer,
			AuthURL:            testdata.AuthURL,
			TokenURL:           testdata.TokenURL,
			NonOIDCUserInfoURL: testdata.NonOIDCUserInfoURL,
			FirewallURL:        testdata.FirewallURL,
			PublicKeyPEM:       testdata.PublicKeyPEM,
		}, a.authnConfig)

	assert.NotNil(t, a.publicKey)
}

func TestAuthDirective(t *testing.T) {
	caddyfileInput := fmt.Sprintf(`{
	order paw_auth before basic_auth
	authn_yaml_file %s
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
`, testdata.AuthnYAML(t))

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

func TestIsAjax(t *testing.T) {
	a := &authModule{}

	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{
			name:     "no headers",
			headers:  map[string]string{},
			expected: false,
		},
		{
			name: "X-Requested-With",
			headers: map[string]string{
				"X-Requested-With": "XMLHttpRequest",
			},
			expected: true,
		},
		{
			name: "Accept application/json",
			headers: map[string]string{
				"Accept": "application/json",
			},
			expected: true,
		},
		{
			name: "Accept containing application/json",
			headers: map[string]string{
				"Accept": "text/html,application/xhtml+xml,application/json;q=0.9",
			},
			expected: true,
		},
		{
			name: "Sec-Fetch-Mode cors",
			headers: map[string]string{
				"Sec-Fetch-Mode": "cors",
			},
			expected: true,
		},
		{
			name: "Sec-Fetch-Mode navigate",
			headers: map[string]string{
				"Sec-Fetch-Mode": "navigate",
			},
			expected: false,
		},
		{
			name: "Sec-Fetch-Mode same-origin",
			headers: map[string]string{
				"Sec-Fetch-Mode": "same-origin",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			assert.Equal(t, tt.expected, a.isAjax(r))
		})
	}
}

func TestAuthDirective_WithWAF(t *testing.T) {
	caddyfileInput := fmt.Sprintf(`{
	order paw_auth before basic_auth
	authn_yaml_file %s
}

example.com {
	paw_auth {
		basic_auth
		client_id the-client-id
		client_secret the-client-secret
		roles role1 role2
		callback_url https://example.com/callback
		waf {
			directives `+"`SecRuleEngine On`"+`
		}
	}
	respond "hi"
}
`, testdata.AuthnYAML(t))

	cfg := caddyConfig(t, caddyfileInput)

	// ProvisionContext provisions and validates the config including waf initialization.
	_, err := caddy.ProvisionContext(cfg)
	assert.NoError(t, err)
}

func TestServeHTTP_WAF_BlocksBeforeAuthAndPublicURLs(t *testing.T) {
	mock, testServer := setupMockAuthnServer(t)
	a := newAuthModule(t, testServer, authTypeBasicAuth)

	u, err := urlMatcherFromStr("path_prefix:/public")
	require.NoError(t, err)
	a.PublicURLs = append(a.PublicURLs, u)

	wafCfg := &waf.Config{
		Directives: `SecRule REQUEST_URI "@contains evil" "id:1001,phase:1,deny,status:403"`,
	}
	wEngine, err := waf.NewWAF(wafCfg, zap.NewNop())
	require.NoError(t, err)
	a.waf = wEngine

	nextCalled := false
	nextHandler := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		return nil
	}}

	// 1. Attack on a public URL -> blocked by WAF despite being public
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/public/evil?foo=bar", nil)
	r.RemoteAddr = "198.51.100.1:12345"

	err = a.ServeHTTP(w, r, nextHandler)
	require.Error(t, err)
	assert.False(t, nextCalled)

	// Verify report sent to firewall with rule ID reason
	require.Len(t, mock.firewallRequests, 1)
	assert.Equal(t, "198.51.100.1", mock.firewallRequests[0].URL.Query().Get("ip"))
	assert.Equal(t, "waf:1001", mock.firewallRequests[0].URL.Query().Get("reason"))

	// 2. Legitimate request on a public URL -> passes WAF and gets served by nextHandler
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "/public/safe", nil)
	r2.RemoteAddr = "198.51.100.1:12345"

	err = a.ServeHTTP(w2, r2, nextHandler)
	require.NoError(t, err)
	assert.True(t, nextCalled)
	assert.Len(t, mock.firewallRequests, 1) // No new firewall report
}

// newAfterAuthModule builds a basic_auth module whose WAF is configured with the
// given after_auth mode. The basic auth cache is preloaded so that authenticated
// requests do not hit the mock authn server.
func newAfterAuthModule(t *testing.T, afterAuth, directives string) (*mockAuthnServer, *authModule) {
	t.Helper()

	mock, testServer := setupMockAuthnServer(t)
	a := newAuthModule(t, testServer, authTypeBasicAuth)

	a.WAFConfig = &waf.Config{Directives: directives, AfterAuth: afterAuth}

	var err error
	a.waf, err = waf.NewWAF(a.WAFConfig, zap.NewNop())
	require.NoError(t, err)
	if afterAuth == waf.AfterAuthDetectOnly {
		a.wafDetectOnly, err = waf.NewWAFDetectOnly(a.WAFConfig, zap.NewNop())
		require.NoError(t, err)
	}

	a.storeBasicAuth("test-user", "test-password", &userInfo{
		Username:   "test-user",
		Roles:      "admin",
		roles:      stringset.New("admin"),
		Expiration: time.Now().Add(time.Hour).Unix(),
	})
	a.basicAuthCache.Wait()

	return mock, a
}

const afterAuthTestDirectives = `
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_URI "@contains attack" "id:6001,phase:1,deny,status:403"
SecRule ARGS_POST:field "@contains attack" "id:6002,phase:2,deny,status:403"
`

func TestServeHTTP_AfterAuthSkip(t *testing.T) {
	mock, a := newAfterAuthModule(t, waf.AfterAuthSkip, afterAuthTestDirectives)

	nextCalled := false
	next := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		return nil
	}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/attack", nil)
	r.RemoteAddr = "198.51.100.7:12345"
	r.SetBasicAuth("test-user", "test-password")

	require.NoError(t, a.ServeHTTP(w, r, next))
	assert.True(t, nextCalled, "authenticated request must reach the upstream")
	assert.Empty(t, mock.firewallRequests, "skip mode must not report authenticated traffic")
}

func TestServeHTTP_AfterAuthDetectOnly(t *testing.T) {
	mock, a := newAfterAuthModule(t, waf.AfterAuthDetectOnly, afterAuthTestDirectives)

	nextCalled := false
	next := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		return nil
	}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/attack", nil)
	r.RemoteAddr = "198.51.100.8:12345"
	r.SetBasicAuth("test-user", "test-password")

	require.NoError(t, a.ServeHTTP(w, r, next))
	assert.True(t, nextCalled, "detect_only must not block authenticated requests")

	require.Len(t, mock.firewallRequests, 1, "the match must still be logged")
	assert.Equal(t, "198.51.100.8", mock.firewallRequests[0].URL.Query().Get("ip"))
	assert.Equal(t, "waf:6001", mock.firewallRequests[0].URL.Query().Get("reason"))
	assert.Equal(t, "false", mock.firewallRequests[0].URL.Query().Get("count"),
		"detect_only must not consume ban allowance")
}

func TestServeHTTP_AfterAuthDetectOnly_CleanRequest(t *testing.T) {
	mock, a := newAfterAuthModule(t, waf.AfterAuthDetectOnly, afterAuthTestDirectives)

	nextCalled := false
	next := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		return nil
	}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/safe", nil)
	r.RemoteAddr = "198.51.100.9:12345"
	r.SetBasicAuth("test-user", "test-password")

	require.NoError(t, a.ServeHTTP(w, r, next))
	assert.True(t, nextCalled)
	assert.Empty(t, mock.firewallRequests)
}

func TestServeHTTP_AfterAuthPhase1Only(t *testing.T) {
	mock, a := newAfterAuthModule(t, waf.AfterAuthPhase1Only, afterAuthTestDirectives)

	next := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	}}

	t.Run("body is not inspected and stays readable", func(t *testing.T) {
		var body string
		nextWithBody := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				return err
			}
			body = string(b)
			w.WriteHeader(http.StatusOK)
			return nil
		}}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/dav/file", strings.NewReader("field=attack"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = "198.51.100.10:12345"
		r.SetBasicAuth("test-user", "test-password")

		require.NoError(t, a.ServeHTTP(w, r, nextWithBody))
		assert.Equal(t, "field=attack", body, "phase1_only must not consume the body")
		assert.Empty(t, mock.firewallRequests)
	})

	t.Run("phase 1 violation is still blocked", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/attack", nil)
		r.RemoteAddr = "198.51.100.11:12345"
		r.SetBasicAuth("test-user", "test-password")

		err := a.ServeHTTP(w, r, next)
		require.Error(t, err)

		var handlerErr caddyhttp.HandlerError
		require.ErrorAs(t, err, &handlerErr)
		assert.Equal(t, http.StatusForbidden, handlerErr.StatusCode)
		require.Len(t, mock.firewallRequests, 1)
		assert.Equal(t, "waf:6001", mock.firewallRequests[0].URL.Query().Get("reason"))
		assert.Empty(t, mock.firewallRequests[0].URL.Query().Get("count"),
			"a blocked request must consume ban allowance")
	})
}

func TestServeHTTP_AfterAuthDetectOnly_PublicURLStillBlocked(t *testing.T) {
	mock, a := newAfterAuthModule(t, waf.AfterAuthDetectOnly, afterAuthTestDirectives)

	u, err := urlMatcherFromStr("path_prefix:/public")
	require.NoError(t, err)
	a.PublicURLs = append(a.PublicURLs, u)

	nextCalled := false
	next := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		return nil
	}}

	// Unauthenticated attack on a public URL must still be blocked, otherwise
	// public endpoints would silently lose WAF coverage in after_auth modes.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/public/attack", nil)
	r.RemoteAddr = "198.51.100.12:12345"

	err = a.ServeHTTP(w, r, next)
	require.Error(t, err)
	assert.False(t, nextCalled)
	require.Len(t, mock.firewallRequests, 1)
	assert.Equal(t, "waf:6001", mock.firewallRequests[0].URL.Query().Get("reason"))
}

func TestServeHTTP_AfterAuthSkip_UnauthenticatedRequestIsChallenged(t *testing.T) {
	mock, a := newAfterAuthModule(t, waf.AfterAuthSkip, afterAuthTestDirectives)

	nextCalled := false
	next := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		return nil
	}}

	// Without a post-auth mode the WAF would answer 403 before the client ever
	// sees the basic-auth challenge. With after_auth set, authentication runs
	// first, so the client gets the 401 it can act on. The WAF still observes the
	// request and feeds the ban pipeline, but must not change the status code.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/attack", nil)
	r.RemoteAddr = "198.51.100.13:12345"

	err := a.ServeHTTP(w, r, next)
	require.Error(t, err)

	var handlerErr caddyhttp.HandlerError
	require.ErrorAs(t, err, &handlerErr)
	assert.Equal(t, http.StatusUnauthorized, handlerErr.StatusCode)
	assert.False(t, nextCalled)
	assert.Equal(t, `Basic realm="restricted"`, w.Header().Get("WWW-Authenticate"))
	require.Len(t, mock.firewallRequests, 1, "unauthenticated matches must still be reported")
	assert.Equal(t, "198.51.100.13", mock.firewallRequests[0].URL.Query().Get("ip"))
	assert.Equal(t, "waf:6001", mock.firewallRequests[0].URL.Query().Get("reason"))
	assert.Empty(t, mock.firewallRequests[0].URL.Query().Get("count"),
		"an unauthenticated match must consume ban allowance")
	assert.Empty(t, mock.firewallRequests[0].URL.Query().Get("weight"),
		"a match without credentials is a single signal, so the parameter is omitted")
}

// TestAuthProvision_PresetWithAfterAuth covers the documented WebDAV setup: a
// bare `preset default` combined with an after_auth mode. Provision builds two
// WAF instances from one Config, so this guards the idempotency of preset
// expansion. Regression: it used to fail with "waf preset and directives are
// mutually exclusive".
func TestAuthProvision_PresetWithAfterAuth(t *testing.T) {
	for _, mode := range []string{"detect_only", "phase1_only", "skip"} {
		t.Run(mode, func(t *testing.T) {
			caddyfileInput := fmt.Sprintf(`{
	order paw_auth before basic_auth
	authn_yaml_file %s
}

example.com {
	paw_auth {
		basic_auth
		client_id the-client-id
		client_secret the-client-secret
		roles admin
		waf {
			preset default
			after_auth %s
		}
	}
	respond "hi"
}
`, testdata.AuthnYAML(t), mode)

			cfg := caddyConfig(t, caddyfileInput)

			provisioned, err := caddy.ProvisionContext(cfg)
			require.NoError(t, err)
			require.NotNil(t, provisioned)
		})
	}
}

func TestAuthDirective_WithWAFInvalidAfterAuth(t *testing.T) {
	caddyfileInput := fmt.Sprintf(`{
	order paw_auth before basic_auth
	authn_yaml_file %s
}

example.com {
	paw_auth {
		basic_auth
		client_id the-client-id
		client_secret the-client-secret
		roles role1
		waf {
			directives `+"`SecRuleEngine On`"+`
			after_auth block_everything
		}
	}
	respond "hi"
}
`, testdata.AuthnYAML(t))

	cfg := caddyConfig(t, caddyfileInput)

	_, err := caddy.ProvisionContext(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown after_auth mode")
}

func TestServeHTTP_AfterAuthPhase1Only_UnauthenticatedMatchIsReported(t *testing.T) {
	mock, a := newAfterAuthModule(t, waf.AfterAuthPhase1Only, afterAuthTestDirectives)

	next := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/attack", nil)
	r.RemoteAddr = "198.51.100.14:12345"

	err := a.ServeHTTP(w, r, next)
	require.Error(t, err)

	var handlerErr caddyhttp.HandlerError
	require.ErrorAs(t, err, &handlerErr)
	assert.Equal(t, http.StatusUnauthorized, handlerErr.StatusCode, "the 401 challenge must survive")
	require.Len(t, mock.firewallRequests, 1)
	assert.Equal(t, "waf:6001", mock.firewallRequests[0].URL.Query().Get("reason"))
}

// TestServeHTTP_AfterAuth_CleanUnauthenticatedRequestIsNotReported pins the other
// side of the ban pipeline: a request that neither trips a rule nor presents
// credentials is what every browser, health check and WebDAV client sends before
// it knows a protected path exists, so it must not cost anything.
func TestServeHTTP_AfterAuth_CleanUnauthenticatedRequestIsNotReported(t *testing.T) {
	mock, a := newAfterAuthModule(t, waf.AfterAuthDetectOnly, afterAuthTestDirectives)

	next := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/safe", nil)
	r.RemoteAddr = "198.51.100.15:12345"

	require.Error(t, a.ServeHTTP(w, r, next))
	assert.Empty(t, mock.firewallRequests, "a first visit without credentials must not be counted")
}

func TestServeHTTP_BlockMode_NoAfterAuthEngine(t *testing.T) {
	mock, a := newAfterAuthModule(t, waf.AfterAuthBlock, afterAuthTestDirectives)
	assert.Nil(t, a.wafDetectOnly, "block mode must not build the detect-only engine")

	nextCalled := false
	next := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		return nil
	}}

	// Unauthenticated attack in block mode is still blocked before checkAuth.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/attack", nil)
	r.RemoteAddr = "198.51.100.16:12345"

	err := a.ServeHTTP(w, r, next)
	require.Error(t, err)

	var handlerErr caddyhttp.HandlerError
	require.ErrorAs(t, err, &handlerErr)
	assert.Equal(t, http.StatusForbidden, handlerErr.StatusCode)
	assert.False(t, nextCalled)
	require.Len(t, mock.firewallRequests, 1)
}

// newServerCookiesAfterAuthModule is newAfterAuthModule for the server_cookies
// auth type: no credentials are preloaded, so every request fails authentication
// via the cookie path.
func newServerCookiesAfterAuthModule(t *testing.T, afterAuth, directives string) (*mockAuthnServer, *authModule) {
	t.Helper()

	mock, testServer := setupMockAuthnServer(t)
	a := newAuthModule(t, testServer, authTypeServerCookies)

	a.WAFConfig = &waf.Config{Directives: directives, AfterAuth: afterAuth}

	var err error
	a.waf, err = waf.NewWAF(a.WAFConfig, zap.NewNop())
	require.NoError(t, err)
	if afterAuth == waf.AfterAuthDetectOnly {
		a.wafDetectOnly, err = waf.NewWAFDetectOnly(a.WAFConfig, zap.NewNop())
		require.NoError(t, err)
	}

	return mock, a
}

// TestServeHTTP_ServerCookies_SingleReportPerRequest is the regression test for
// the double counting bug: server_cookies reported the invalid token and the
// post-auth WAF pass reported the very same request again, so one request cost
// two ban-pipeline tokens.
func TestServeHTTP_ServerCookies_SingleReportPerRequest(t *testing.T) {
	next := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	}}

	tests := []struct {
		name       string
		path       string
		cookie     bool
		wantReason string
	}{
		{
			// Both signals are independent (a forged JWT and a malicious payload),
			// so the request is reported once, carrying both reasons.
			name:       "invalid token plus WAF match counts once with both reasons",
			path:       "/attack",
			cookie:     true,
			wantReason: "waf:6001 | invalid token on path: /attack",
		},
		{
			name:       "invalid token without WAF match keeps its own reason",
			path:       "/safe",
			cookie:     true,
			wantReason: "invalid token on path: /safe",
		},
		{
			name:       "missing access token redirects and is not counted",
			path:       "/safe",
			cookie:     false,
			wantReason: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, a := newServerCookiesAfterAuthModule(t, waf.AfterAuthDetectOnly, afterAuthTestDirectives)

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, tt.path, nil)
			r.RemoteAddr = "198.51.100.20:12345"
			if tt.cookie {
				r.AddCookie(&http.Cookie{Name: cookieKeyAccessToken, Value: "not-a-jwt"})
			}

			// 302 (redirect to login) and 401 are both expected; only the report
			// count matters here.
			_ = a.ServeHTTP(w, r, next)

			if tt.wantReason == "" {
				assert.Empty(t, mock.firewallRequests)
				return
			}
			require.Len(t, mock.firewallRequests, 1, "one request must produce exactly one count")
			assert.Equal(t, tt.wantReason, mock.firewallRequests[0].URL.Query().Get("reason"))
		})
	}
}

// TestServeHTTP_ServerCookies_CallbackFailureCountsOnce covers the 400 branch,
// which reported "callback: no auth code" and could then report the same request
// a second time from the WAF pass.
func TestServeHTTP_ServerCookies_CallbackFailureCountsOnce(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantReason string
	}{
		{"no auth code", "/paw/callback?state=x", "callback: no auth code"},
		{"no state", "/paw/callback?code=x", "callback: no state"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, a := newServerCookiesAfterAuthModule(t, waf.AfterAuthDetectOnly, afterAuthTestDirectives)

			next := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
				w.WriteHeader(http.StatusOK)
				return nil
			}}

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, tt.path, nil)
			r.RemoteAddr = "198.51.100.21:12345"

			require.Error(t, a.ServeHTTP(w, r, next))

			require.Len(t, mock.firewallRequests, 1, "one request must produce exactly one count")
			assert.Equal(t, tt.wantReason, mock.firewallRequests[0].URL.Query().Get("reason"))
		})
	}
}

// TestServeHTTP_BlockMode_ReportsAtMostOnce makes sure the single-report
// guarantee also holds in the default blocking mode, where no post-auth engine
// exists.
func TestServeHTTP_BlockMode_ReportsAtMostOnce(t *testing.T) {
	mock, a := newAfterAuthModule(t, waf.AfterAuthBlock, afterAuthTestDirectives)

	nextCalled := false
	next := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		return nil
	}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/attack", nil)
	r.RemoteAddr = "198.51.100.22:12345"

	err := a.ServeHTTP(w, r, next)
	require.Error(t, err)
	assert.False(t, nextCalled)

	var handlerErr caddyhttp.HandlerError
	require.ErrorAs(t, err, &handlerErr)
	assert.Equal(t, http.StatusForbidden, handlerErr.StatusCode)

	require.Len(t, mock.firewallRequests, 1, "one request must produce exactly one count")
	assert.Equal(t, "waf:6001", mock.firewallRequests[0].URL.Query().Get("reason"))
}

// TestServeHTTP_Phase1Modes_DoNotBufferUnauthenticatedBodies guards the promise
// phase1_only and skip make to upload-heavy deployments: bodies are never
// buffered. Unauthenticated requests are still inspected, but through phase 1
// only, so a body-level rule cannot be found and the body is left untouched.
func TestServeHTTP_Phase1Modes_DoNotBufferUnauthenticatedBodies(t *testing.T) {
	for _, mode := range []string{waf.AfterAuthPhase1Only, waf.AfterAuthSkip} {
		t.Run(mode, func(t *testing.T) {
			mock, a := newAfterAuthModule(t, mode, afterAuthTestDirectives)
			assert.Nil(t, a.wafDetectOnly, "only detect_only needs a second engine")

			nextCalled := false
			next := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
				return nil
			}}

			body := &countingReader{r: strings.NewReader("field=attack")}
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/dav/file", body)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.RemoteAddr = "198.51.100.30:12345"

			require.Error(t, a.ServeHTTP(w, r, next))
			assert.False(t, nextCalled)
			assert.Zero(t, body.reads, "the body must not be read for unauthenticated requests")
			assert.Empty(t, mock.firewallRequests, "a phase-2 rule cannot match without the body")
		})
	}
}

// TestServeHTTP_Skip_UnauthenticatedPhase1MatchIsReported keeps the ban pipeline
// fed even though skip mode never inspects bodies: a phase-1 rule still matches.
func TestServeHTTP_Skip_UnauthenticatedPhase1MatchIsReported(t *testing.T) {
	mock, a := newAfterAuthModule(t, waf.AfterAuthSkip, afterAuthTestDirectives)

	next := &mockCaddyHTTPHandler{handler: func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/attack", nil)
	r.RemoteAddr = "198.51.100.31:12345"

	err := a.ServeHTTP(w, r, next)
	require.Error(t, err)

	var handlerErr caddyhttp.HandlerError
	require.ErrorAs(t, err, &handlerErr)
	assert.Equal(t, http.StatusUnauthorized, handlerErr.StatusCode)
	require.Len(t, mock.firewallRequests, 1)
	assert.Equal(t, "waf:6001", mock.firewallRequests[0].URL.Query().Get("reason"),
		"the interruption is discarded but its rule ID is still reported")
}

// countingReader counts how many bytes were read from the wrapped reader.
type countingReader struct {
	r     *strings.Reader
	reads int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.reads += n
	return n, err
}
