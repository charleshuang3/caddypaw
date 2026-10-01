package oidc

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type wellKnownConfigResponse struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	ResponseTypes         []string `json:"response_types_supported"`
	GrantTypes            []string `json:"grant_types_supported"`
	TokenEndpointAuth     []string `json:"token_endpoint_auth_methods_supported"`
	Scopes                []string `json:"scopes_supported"`
}

// handleWellKnownConfig returns the OIDC configuration.
func (o *OpenIDProvider) handleWellKnownConfig(c *gin.Context) {
	config := &wellKnownConfigResponse{
		Issuer:                o.config.Issuer,
		AuthorizationEndpoint: o.config.Issuer + "/authorize",
		TokenEndpoint:         o.config.Issuer + "/token",
		JWKSURI:               o.config.Issuer + "/.well-known/jwks.json",
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
	c.JSON(http.StatusOK, config)
}

// handleJWKS returns the JSON Web Key Set for token verification.
func (o *OpenIDProvider) handleJWKS(c *gin.Context) {
	jwks := map[string]interface{}{
		"keys": []interface{}{o.publicKey},
	}
	c.JSON(http.StatusOK, jwks)
}
