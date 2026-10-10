package caddypaw

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/charleshuang3/caddypaw/pkg/caddypaw/config"
	"github.com/charleshuang3/caddypaw/pkg/caddypaw/testdata"
)

func TestParseGlobalOptionAuthnYAMLFilePath(t *testing.T) {
	caddyfileInput := fmt.Sprintf(`{
	authn_yaml_file %s
}

example.com {
	respond "hi"
}
`, testdata.AuthnYAML(t))

	cfg := caddyConfig(t, caddyfileInput)

	rawAuthn, ok := cfg.AppsRaw[globalOptionAppName]
	require.True(t, ok)

	jsonStr, err := rawAuthn.MarshalJSON()
	require.NoError(t, err)

	got := &globalOptionModule{}
	err = json.Unmarshal(jsonStr, got)
	require.NoError(t, err)

	want := &globalOptionModule{
		AuthnConfig: &config.AuthnConfig{
			Issuer:             testdata.Issuer,
			AuthURL:            testdata.AuthURL,
			TokenURL:           testdata.TokenURL,
			NonOIDCUserInfoURL: testdata.NonOIDCUserInfoURL,
			FirewallURL:        testdata.FirewallURL,
			PublicKeyPEM:       testdata.PublicKeyPEM,
		},
	}

	assert.Equal(t, want, got)
}

func TestGlobalOption_Provision(t *testing.T) {
	t.Run("nil AuthnConfig returns error", func(t *testing.T) {
		g := &globalOptionModule{}
		ctx, _ := caddy.NewContext(caddy.Context{Context: t.Context()})
		err := g.Provision(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authn_yaml_file is not configured")
	})

	t.Run("valid AuthnConfig provisions successfully", func(t *testing.T) {
		conf, err := config.LoadFromFile(testdata.AuthnYAML(t))
		require.NoError(t, err)
		g := &globalOptionModule{
			AuthnConfig: conf,
		}
		ctx, _ := caddy.NewContext(caddy.Context{Context: t.Context()})
		err = g.Provision(ctx)
		require.NoError(t, err)
		assert.NotNil(t, g.publicKey)
	})
}

func TestGlobalOption_FirewallURL(t *testing.T) {
	g := &globalOptionModule{}
	assert.Empty(t, g.FirewallURL())

	g.AuthnConfig = &config.AuthnConfig{FirewallURL: "http://127.0.0.1:8080"}
	assert.Equal(t, "http://127.0.0.1:8080", g.FirewallURL())
}

func caddyConfig(t *testing.T, input string) *caddy.Config {
	t.Helper()

	adapter := caddyfile.Adapter{ServerType: &httpcaddyfile.ServerType{}}
	adaptedJSON, warnings, err := adapter.Adapt([]byte(input), nil)
	require.NoError(t, err)
	require.Empty(t, warnings)

	cfg := &caddy.Config{}
	err = caddy.StrictUnmarshalJSON(adaptedJSON, cfg)
	require.NoError(t, err)

	return cfg
}
