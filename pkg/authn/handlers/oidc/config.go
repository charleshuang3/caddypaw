package oidc

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleLogin struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	RedirectURI  string `yaml:"redirect_uri"`
}

var (
	// tests use this to override to test server
	tokenExchangeEndpoint string
)

func (g *GoogleLogin) oauth2Config() *oauth2.Config {
	endpoints := google.Endpoint
	if tokenExchangeEndpoint != "" {
		endpoints.TokenURL = tokenExchangeEndpoint
	}

	return &oauth2.Config{
		ClientID:     g.ClientID,
		ClientSecret: g.ClientSecret,
		RedirectURL:  g.RedirectURI,
		Scopes:       []string{"profile", "email", "openid"},
		Endpoint:     endpoints,
	}
}

type SSOConfig struct {
	Google GoogleLogin `yaml:"google"`
}

type OIDCProviderConfig struct {
	// Title of the OIDC Provider.
	Title string `yaml:"title"`

	// PrivateKeyPEM is RSA 256 private key in PEM format
	PrivateKeyPEM string `yaml:"private_key_pem"`

	// Issuer is the url of this OIDC Provider.
	Issuer string `yaml:"issuer"`

	SSO SSOConfig `yaml:"sso"`
}

func (c *OIDCProviderConfig) Validate() {
	if c.Title == "" {
		logger.Fatal().Msg("OIDCProviderConfig: Title is missing")
	}
	if c.PrivateKeyPEM == "" {
		logger.Fatal().Msg("OIDCProviderConfig: PrivateKeyPEM is missing")
	}
	if c.Issuer == "" {
		logger.Fatal().Msg("OIDCProviderConfig: Issuer is missing")
	}
	if c.SSO.Google.ClientID == "" {
		logger.Fatal().Msg("OIDCProviderConfig: Google ClientID is missing")
	}
	if c.SSO.Google.ClientSecret == "" {
		logger.Fatal().Msg("OIDCProviderConfig: Google ClientSecret is missing")
	}
	if c.SSO.Google.RedirectURI == "" {
		logger.Fatal().Msg("OIDCProviderConfig: Google RedirectURI is missing")
	}
}
