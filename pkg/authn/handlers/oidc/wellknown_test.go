package oidc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/charleshuang3/caddypaw/pkg/authn/testdata"
)

const (
	// generated on jwt.io with the key in testdata/
	testJWT = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XZiPTzgbemf4CX9Dr2xjGHrayl0p51kQwjKnS2mCOoG4cJHGOkzrQ-fTEIe89p1SucUW1bb7Y3NYichfwHzLJcq5WlVnqRmPOdyVRf21V1tzAkzWiqAvlOXqCJVElURfBBff52WsoV41-jc3QCVHMNO9uZQAfVZV8OGsHmiiX-3r5gIG1u2DAh9AcYP1PZf9wt6v01ylQoS5wYZYf29SoufbYmpZS5_dvNLqInRxaoYwVMUSByALiLGVbMs4exzvIjNAkFE4ymEmGR1lTjmYZrjT2a34IDDsrIlNxh6j-Vvx4SK286dz7JYQgNGhgeA02jchTqx9pPpBdzzvsdB7Rg`
)

func TestPublicKey(t *testing.T) {
	provider, _, _ := setupTestProvider(t)
	pubPem, err := jwk.Pem(provider.publicKey)
	require.NoError(t, err)
	assert.Equal(t, testdata.PublicKeyPEM, string(pubPem))
}

func TestHandleWellKnownConfig(t *testing.T) {
	_, _, router := setupTestProvider(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	body, err := io.ReadAll(rec.Body)
	require.NoError(t, err)

	got := &wellKnownConfigResponse{}
	err = json.Unmarshal(body, got)
	require.NoError(t, err)

	want := &wellKnownConfigResponse{
		Issuer:                "http://localhost:8080/oauth2",
		AuthorizationEndpoint: "http://localhost:8080/oauth2/authorize",
		TokenEndpoint:         "http://localhost:8080/oauth2/token",
		JWKSURI:               "http://localhost:8080/oauth2/.well-known/jwks.json",
		ResponseTypes:         []string{"code"}, // only code flow is supported
		GrantTypes:            []string{"authorization_code", "refresh_token"},
		TokenEndpointAuth:     []string{"client_secret_post"},
		Scopes: []string{
			"openid",
			"profile",
			"offline_access",
			"email",
		},
	}
	assert.Equal(t, want, got)
}

func TestHandleWellKnownConfig_GOOIDCNewProvider(t *testing.T) {
	provider, _, router := setupTestProvider(t)

	// Start a test server to serve the JWKS
	ts := httptest.NewServer(router)
	defer ts.Close()

	issuerURL := ts.URL + "/oauth2"
	provider.config.Issuer = ts.URL + "/oauth2"

	ctx := context.Background()
	oidcProvider, err := gooidc.NewProvider(ctx, issuerURL)
	require.NoError(t, err)

	assert.Equal(t, oauth2.Endpoint{
		AuthURL:  issuerURL + "/authorize",
		TokenURL: issuerURL + "/token",
	}, oidcProvider.Endpoint())
}

func TestHandleJWKS(t *testing.T) {
	_, _, router := setupTestProvider(t)

	// Start a test server to serve the JWKS
	ts := httptest.NewServer(router)
	defer ts.Close()

	// Use coreos/go-oidc to fetch the JWKS
	ctx := context.Background()
	keySet := gooidc.NewRemoteKeySet(ctx, ts.URL+"/oauth2/.well-known/jwks.json")

	// Attempt to fetch keys to verify no errors
	keys, err := keySet.VerifySignature(ctx, testJWT)
	assert.NoError(t, err, "Failed to fetch JWKS using coreos/go-oidc")
	assert.NotNil(t, keys, "No keys returned from JWKS endpoint")
}
