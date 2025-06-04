package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/charleshuang3/caddypaw/internal/testdata"
)

func TestLoadFromFile(t *testing.T) {
	conf, err := LoadFromFile(`../testdata/test.yaml`)
	require.NoError(t, err)

	assert.Equal(t, &AuthnConfig{
		Issuer:             "http://example.com:8443/oauth2",
		AuthURL:            "http://example.com:8443/oauth2/authorize",
		TokenURL:           "http://example.com:8443/oauth2/token",
		NonOIDCUserInfoURL: "http://example.com:8443/user/info",
		FirewallURL:        "http://127.0.0.1:8444/",
		PublicKeyPEM:       testdata.PublicKeyPEM,
	}, conf)

	assert.NotNil(t, conf.GetPublicKey())
}
