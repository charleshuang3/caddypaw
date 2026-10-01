package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/charleshuang3/caddypaw/pkg/caddypaw/testdata"
)

func TestLoadFromFile(t *testing.T) {
	conf, err := LoadFromFile(testdata.AuthnYAML(t))
	require.NoError(t, err)

	assert.Equal(t, &AuthnConfig{
		Issuer:             testdata.Issuer,
		AuthURL:            testdata.AuthURL,
		TokenURL:           testdata.TokenURL,
		NonOIDCUserInfoURL: testdata.NonOIDCUserInfoURL,
		FirewallURL:        testdata.FirewallURL,
		PublicKeyPEM:       testdata.PublicKeyPEM,
	}, conf)

	assert.NotNil(t, conf.GetPublicKey())
}
