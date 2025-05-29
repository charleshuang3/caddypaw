package caddypaw

import (
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/charleshuang3/caddypaw/internal/config"
	"github.com/charleshuang3/caddypaw/internal/testdata"
)

func TestParseGlobalOptionAuthnYAMLFilePath(t *testing.T) {
	caddyfileInput := `{
	authn_yaml_file internal/testdata/test.yaml
}

example.com {
	respond "hi"
}
`

	adapter := caddyfile.Adapter{ServerType: &httpcaddyfile.ServerType{}}
	adaptedJSON, warnings, err := adapter.Adapt([]byte(caddyfileInput), nil)
	require.NoError(t, err)
	require.Empty(t, warnings)

	cfg := &caddy.Config{}
	err = caddy.StrictUnmarshalJSON(adaptedJSON, cfg)
	require.NoError(t, err)

	rawAuthn, ok := cfg.AppsRaw[globalOptionAppName]
	require.True(t, ok)

	jsonStr, err := rawAuthn.MarshalJSON()
	require.NoError(t, err)

	got := &globalOptionModule{}
	err = json.Unmarshal(jsonStr, got)
	require.NoError(t, err)

	want := &globalOptionModule{
		AuthnConfig: &config.AuthnConfig{
			AuthURL:      "https://example.com:8443/oauth2/authorize",
			TokenURL:     "https://example.com:8443/oauth2/token",
			FirewallURL:  "http://127.0.0.1:8444/",
			PublicKeyPEM: testdata.PublicKeyPEM,
		},
	}

	assert.Equal(t, want, got)
}
