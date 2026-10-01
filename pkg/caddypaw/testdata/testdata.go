// Package testdata provides shared fixtures for the caddypaw plugin tests.
//
// The RSA test key pair is owned by pkg/authn/testdata (the JWT signer) and
// only re-exported here, so there is a single source of truth for test key
// material. The authn gateway config is generated from those same values
// instead of being checked in as a separate YAML file.
package testdata

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"

	authntestdata "github.com/charleshuang3/caddypaw/pkg/authn/testdata"
)

// Authn gateway config values, asserted by the config and globaloption tests.
const (
	Issuer             = "http://example.com:8443/oauth2"
	AuthURL            = "http://example.com:8443/oauth2/authorize"
	TokenURL           = "http://example.com:8443/oauth2/token"
	NonOIDCUserInfoURL = "http://example.com:8443/user/info"
	FirewallURL        = "http://127.0.0.1:8444/"
)

// Key material re-exported from pkg/authn/testdata, the single owner.
var (
	PublicKeyPEM  = authntestdata.PublicKeyPEM
	PrivateKeyPEM = authntestdata.PrivateKeyPEM
	PublicKey, _  = jwk.ParseKey([]byte(PublicKeyPEM), jwk.WithPEM(true))
	PrivateKey, _ = jwk.ParseKey([]byte(PrivateKeyPEM), jwk.WithPEM(true))
)

// AuthnYAML writes the authn gateway config (the file loaded through the
// `authn_yaml_file` global option) to a temp file and returns its path.
func AuthnYAML(t *testing.T) string {
	t.Helper()

	data, err := yaml.Marshal(map[string]string{
		"issuer":                Issuer,
		"auth_url":              AuthURL,
		"token_url":             TokenURL,
		"non_oidc_userinfo_url": NonOIDCUserInfoURL,
		"firewall_url":          FirewallURL,
		"public_key_pem":        PublicKeyPEM,
	})
	require.NoError(t, err)

	p := filepath.Join(t.TempDir(), "authn.yaml")
	require.NoError(t, os.WriteFile(p, data, 0o600))
	return p
}
