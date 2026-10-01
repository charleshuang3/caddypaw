package oidc

import (
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/rs/zerolog/log"

	"github.com/charleshuang3/caddypaw/pkg/authn/gormw"
	"github.com/charleshuang3/caddypaw/pkg/authn/storage"
)

var (
	logger = log.With().Str("component", "oidc-provider").Logger()
)

type OpenIDProvider struct {
	config *OIDCProviderConfig
	db     *gormw.DB

	privateKey jwk.Key
	publicKey  jwk.Key

	authStateStorage *storage.AuthStateStorage
	authCodeStorage  *storage.AuthCodeStorage
}

func NewOpenIDProvider(config *OIDCProviderConfig, db *gormw.DB) *OpenIDProvider {
	priv, err := jwk.ParseKey([]byte(config.PrivateKeyPEM), jwk.WithPEM(true))
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to parse private key")
	}

	pub, err := priv.PublicKey()
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to generate public key")
	}

	return &OpenIDProvider{
		config:           config,
		db:               db,
		privateKey:       priv,
		publicKey:        pub,
		authStateStorage: storage.NewAuthStateStorage(),
		authCodeStorage:  storage.NewAuthCodeStorage(),
	}
}

func (o *OpenIDProvider) RegisterHandlers(rg *gin.RouterGroup) {
	oauth2Routes := rg.Group("/oauth2")
	{
		// Authorization Endpoint
		oauth2Routes.GET("/authorize", o.handleAuthorize)
		// Token Endpoint
		oauth2Routes.POST("/token", o.handleToken)
		// UserInfo Endpoint. OIDC Core §5.3.1 requires both GET and POST.
		oauth2Routes.GET("/userinfo", o.handleUserInfo)
		oauth2Routes.POST("/userinfo", o.handleUserInfo)
		// Well-Known Configuration Endpoint
		oauth2Routes.GET("/.well-known/openid-configuration", o.handleWellKnownConfig)
		// JWKS Endpoint
		oauth2Routes.GET("/.well-known/jwks.json", o.handleJWKS)
	}

	// ---- Identity broker: SSO callback ----
	ssoRoutes := rg.Group("/sso")
	{
		ssoRoutes.GET("/google/callback", o.handleGoogleCallback)
	}

	// ---- Not standard oauth endpoints ----
	userRoutes := rg.Group("/user")
	{
		// Username + password login
		userRoutes.POST("/login", o.handleLogin)

		// Username + password register page
		userRoutes.GET("/register", o.registerPage)

		// Username + password register request
		userRoutes.POST("/register", o.handleUserRegister)

		// Retrive user info from username + password for http basic auth allow client
		userRoutes.POST("/info", o.handleNotOIDCUserInfo)
	}
}
