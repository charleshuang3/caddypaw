// Package testenv provides an in-process E2E test environment that spins up:
//
//   - a mock upstream app (echo server),
//   - a real Authn server (SQLite in-memory, memory firewall provider),
//   - a real Caddy instance with the caddypaw plugin proxying to the upstream.
//
// Everything runs on 127.0.0.1 random ports; no external network, cloud
// credentials, or hardware firewalls are required.
package testenv

import (
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"

	// Register standard Caddy directives (reverse_proxy, handle, ...) and
	// the caddypaw plugin (paw_auth directive + authn_yaml_file global
	// option) so the caddyfile adapter can parse the test Caddyfile.
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	"github.com/gin-gonic/gin"
	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/charleshuang3/caddypaw/pkg/caddypaw"

	authnconfig "github.com/charleshuang3/caddypaw/pkg/authn/config"
	"github.com/charleshuang3/caddypaw/pkg/authn/gormw"
	fwhandler "github.com/charleshuang3/caddypaw/pkg/authn/handlers/firewall"
	"github.com/charleshuang3/caddypaw/pkg/authn/handlers/oidc"
	"github.com/charleshuang3/caddypaw/pkg/authn/handlers/statisfiles"
	"github.com/charleshuang3/caddypaw/pkg/authn/models"
	"github.com/charleshuang3/caddypaw/pkg/firewall/memory"
)

// Fixed identities shared across the E2E suite.
const (
	TestClientID     = "e2e-client"
	TestClientSecret = "e2e-secret"
	TestUsername     = "e2euser"
	TestPassword     = "E2eTestPassw0rd!"
	TestRole         = "admin"

	// GatewayPort is the fixed port the Caddy gateway listens on. Tests run
	// sequentially, so one port is enough.
	GatewayPort = "127.0.0.1:18080"
)

// Cluster is the full in-process E2E stack. Create with New; it cleans itself
// up automatically when the test finishes.
type Cluster struct {
	t *testing.T

	// Upstream is the mock backend app behind Caddy.
	Upstream *UpstreamEcho

	// AuthnURL is the base URL of the authn OIDC server.
	AuthnURL string
	// FirewallURL is the base URL of the authn firewall handlers (/logerr, /ban).
	FirewallURL string
	// CaddyURL is the base URL of the Caddy gateway protecting the upstream.
	CaddyURL string

	// MemFirewall records ban events reported to the authn firewall.
	MemFirewall *memory.Firewall

	db *gormw.DB

	oidcSrv *httptest.Server
	fwSrv   *httptest.Server
}

// UpstreamEcho is a mock upstream that echoes request details.
type UpstreamEcho struct {
	srv *httptest.Server

	mu       sync.Mutex
	requests []http.Header
}

func (u *UpstreamEcho) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.requests = append(u.requests, r.Header.Clone())
		u.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "hello from upstream")
	}
}

// Requests returns a copy of the headers received by the upstream.
func (u *UpstreamEcho) Requests() []http.Header {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]http.Header, len(u.requests))
	copy(out, u.requests)
	return out
}

// New starts the mock upstream and the authn server, and seeds a caddypaw
// test user and client. Call Cluster.StartCaddy to also bring up the gateway.
func New(t *testing.T) *Cluster {
	t.Helper()

	gin.SetMode(gin.TestMode)

	c := &Cluster{t: t}

	// 1. Mock upstream app.
	c.Upstream = &UpstreamEcho{}
	c.Upstream.srv = httptest.NewServer(c.Upstream.handler())
	t.Cleanup(c.Upstream.srv.Close)

	// 2. Authn servers + seeded data.
	c.startAuthn()
	c.seed()

	return c
}

func (c *Cluster) startAuthn() {
	t := c.t
	t.Helper()

	cityDB, asnDB := testMMDBPaths(t)
	// The updated-* paths must exist; point them at copies of the same test DBs.
	updatedCity := filepath.Join(t.TempDir(), "city.mmdb")
	updatedASN := filepath.Join(t.TempDir(), "asn.mmdb")
	require.NoError(t, copyFile(cityDB, updatedCity))
	require.NoError(t, copyFile(asnDB, updatedASN))

	cfg := &authnconfig.Config{
		GinMode: gin.TestMode,
		OIDC: oidc.OIDCProviderConfig{
			Title:         "e2e-authn",
			PrivateKeyPEM: string(mustRead(t, "keys/private_key.pem")),
			Issuer:        "http://127.0.0.1/oauth2", // replaced below
		},
		DB: gormw.Config{},
		Firewall: fwhandler.FirewallConfig{
			Provider:          "memory",
			BanMinutes:        10,
			Whitelist:         []string{"127.0.0.1"}, // never ban the test runner
			Forgivable:        fwhandler.ForgivableError{DurationInMinute: 10, Count: 3},
			CityDBFile:        cityDB,
			UpdatedCityDBFile: updatedCity,
			ASNDBFile:         asnDB,
			UpdatedASNDBFile:  updatedASN,
		},
	}

	// OIDC server.
	db, err := gormw.Open(&cfg.DB)
	require.NoError(t, err)
	require.NoError(t, db.Migrate())
	c.db = db

	provider := oidc.NewOpenIDProvider(&cfg.OIDC, db)
	router := gin.New()
	provider.RegisterHandlers(router.Group("/"))
	statisfiles.RegisterHandlers(router.Group("/"))
	c.oidcSrv = httptest.NewServer(router)
	t.Cleanup(c.oidcSrv.Close)
	c.AuthnURL = c.oidcSrv.URL
	cfg.OIDC.Issuer = c.AuthnURL + "/oauth2"

	// Firewall handler server.
	fwMiddleware := fwhandler.New(&cfg.Firewall)
	c.MemFirewall = fwMiddleware.MemoryFirewall()
	require.NotNil(t, c.MemFirewall)

	fwRouter := gin.New()
	fwRouter.Use(fwMiddleware.Middleware())
	fwMiddleware.RegisterHandlers(fwRouter.Group("/"))
	c.fwSrv = httptest.NewServer(fwRouter)
	t.Cleanup(c.fwSrv.Close)
	c.FirewallURL = c.fwSrv.URL
}

func (c *Cluster) seed() {
	t := c.t
	t.Helper()

	hashed, err := bcrypt.GenerateFromPassword([]byte(TestPassword), bcrypt.MinCost)
	require.NoError(t, err)

	user := &models.User{
		Username:       TestUsername,
		Name:           "E2E User",
		Email:          "e2e@example.com",
		HashedPassword: string(hashed),
		Roles:          TestRole,
	}
	require.NoError(t, c.db.Create(user).Error)

	client := &models.Client{
		ClientID:           TestClientID,
		ClientName:         "E2E Client",
		Secret:             TestClientSecret,
		AllowedScopes:      "openid profile email offline_access",
		RedirectURIPrefixs: "http://127.0.0.1,http://localhost",
		AllowPasswordLogin: true,
		AccessTokenTTL:     3600,
		RefreshTokenTTL:    86400,
	}
	require.NoError(t, c.db.Create(client).Error)
}

// StartCaddy runs a real Caddy instance with the given Caddyfile content,
// after replacing the placeholders {upstream}, {authn}, and {firewall} with
// this cluster's URLs, and {port} with the fixed gateway address. Caddy is
// stopped when the test finishes. Returns the gateway base URL.
func (c *Cluster) StartCaddy(caddyfileContent string) string {
	c.t.Helper()

	c.t.Cleanup(func() {
		_ = caddy.Stop()
	})

	content := caddyfileContent
	for k, v := range map[string]string{
		"{upstream}": c.Upstream.srv.URL,
		"{authn}":    c.AuthnURL,
		"{firewall}": c.FirewallURL,
		"{port}":     GatewayPort,
	} {
		content = strings.ReplaceAll(content, k, v)
	}

	adapter := caddyfile.Adapter{ServerType: &httpcaddyfile.ServerType{}}
	cfgJSON, warnings, err := adapter.Adapt([]byte(content), nil)
	require.NoError(c.t, err)
	for _, w := range warnings {
		c.t.Logf("caddyfile warning: %v", w)
	}

	require.NoError(c.t, caddy.Load(cfgJSON, true))

	c.waitForListen(GatewayPort)
	c.CaddyURL = "http://" + GatewayPort
	return c.CaddyURL
}

func (c *Cluster) waitForListen(addr string) {
	c.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			c.t.Fatalf("caddy did not start listening on %s", addr)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Client returns an HTTP client with a cookie jar for walking OIDC flows.
// It does not follow redirects, so tests can drive them manually.
func (c *Cluster) Client() *http.Client {
	jar, err := cookiejar.New(nil)
	require.NoError(c.t, err)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// testMMDBPaths returns the shared GeoLite2 test databases.
func testMMDBPaths(t *testing.T) (city, asn string) {
	t.Helper()
	base := repoRoot(t)
	return filepath.Join(base, "test/testdata/mmdb/GeoLite2-City-Test.mmdb"),
		filepath.Join(base, "test/testdata/mmdb/GeoLite2-ASN-Test.mmdb")
}

func repoRoot(t *testing.T) string {
	t.Helper()
	// This package lives at <root>/test/e2e/testenv.
	dir, err := os.Getwd()
	require.NoError(t, err)
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("go.mod not found")
	return ""
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}

func mustRead(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "test/testdata", rel))
	require.NoError(t, err)
	return data
}

// WriteAuthnGatewayYAML writes a caddypaw gateway config (the file loaded via
// the `authn_yaml_file` global option) to a temp file and returns its path.
func WriteAuthnGatewayYAML(t *testing.T, authURL, tokenURL, userInfoURL, firewallURL string) string {
	t.Helper()
	cfg := map[string]any{
		"issuer":                authURL + "/oauth2",
		"auth_url":              authURL + "/oauth2/authorize",
		"token_url":             tokenURL,
		"non_oidc_userinfo_url": userInfoURL,
		"firewall_url":          firewallURL,
		"public_key_pem":        string(mustRead(t, "keys/public_key.pem")),
		"client_id":             TestClientID,
		"client_secret":         TestClientSecret,
	}
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "authn.yaml")
	require.NoError(t, os.WriteFile(p, data, 0o600))
	return p
}
