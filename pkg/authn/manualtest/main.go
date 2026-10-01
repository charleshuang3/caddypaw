package main

import (
	"fmt"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-co-op/gocron/v2"
	"github.com/goccy/go-yaml"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"github.com/charleshuang3/caddypaw/pkg/authn/config"
	"github.com/charleshuang3/caddypaw/pkg/authn/gormw"
	"github.com/charleshuang3/caddypaw/pkg/authn/handlers/oidc"
	"github.com/charleshuang3/caddypaw/pkg/authn/handlers/statisfiles"
	"github.com/charleshuang3/caddypaw/pkg/authn/manualtest/internal/testapp"
	"github.com/charleshuang3/caddypaw/pkg/authn/models"
	"github.com/charleshuang3/caddypaw/pkg/authn/storage"
	"github.com/charleshuang3/caddypaw/pkg/authn/testdata"
)

func main() {
	file, err := os.Open(".local/google.yaml")
	if err != nil {
		log.Fatal().Err(err).Msgf("failed to open config file")
	}
	defer func() {
		_ = file.Close()
	}()

	sso := &oidc.SSOConfig{}

	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(sso); err != nil {
		log.Fatal().Err(err).Msg("failed to decode config file")
	}

	cfg := config.Config{
		Port:    8081,
		GinMode: "debug",
		OIDC: oidc.OIDCProviderConfig{
			Title:         "Test OIDC Provider",
			PrivateKeyPEM: testdata.PrivateKeyPEM,
			Issuer:        "http://127.0.0.1:8081/oauth2",
			SSO: oidc.SSOConfig{
				Google: oidc.GoogleLogin{
					ClientID:     sso.Google.ClientID,
					ClientSecret: sso.Google.ClientSecret,
					RedirectURI:  "http://127.0.0.1:8081/sso/google/callback",
				},
			},
		},
		DB: gormw.Config{},
	}

	// Initialize database
	db, err := gormw.Open(&cfg.DB)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to open database")
	}
	if err := db.Migrate(); err != nil {
		log.Fatal().Err(err).Msg("Failed to migrate database")
	}

	// cron schedule
	scheduler, _ := gocron.NewScheduler()
	scheduler.Start()

	storage.RegisterRefreshTokensCleaner(scheduler, db)

	preloadData(db)

	// Set up Gin router
	gin.SetMode(cfg.GinMode)
	router := gin.Default()

	// Register OIDC handlers
	oidcProvider := oidc.NewOpenIDProvider(&cfg.OIDC, db)
	oidcProvider.RegisterHandlers(router.Group("/"))

	statisfiles.RegisterHandlers(router.Group("/"))

	// Start oidc server
	go func() {
		addr := fmt.Sprintf(":%d", cfg.Port)
		log.Info().Msgf("Starting server on %s", addr)
		if err := router.Run(addr); err != nil {
			log.Fatal().Err(err).Msg("Failed to start server")
		}
	}()

	time.Sleep(2 * time.Second)

	// Start the test app
	log.Info().Msgf("Starting test app server on 8082")
	testapp.NewServer(8082)
}

func preloadData(db *gormw.DB) {
	// Add a client
	client := &models.Client{
		ClientID:           "test-client-id",
		Secret:             "test-client-secret",
		RedirectURIPrefixs: "http://127.0.0.1:8082/callback",
		AllowedScopes:      "openid profile email offline_access",
		AllowPasswordLogin: true,
		AllowGoogleLogin:   true,
		AccessTokenTTL:     600,
		RefreshTokenTTL:    3600 * 24,
	}
	if err := db.Create(client).Error; err != nil {
		log.Fatal().Err(err).Msg("Failed to create client")
	}

	// Add a user
	secret, err := bcrypt.GenerateFromPassword([]byte("123456"), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to generate bcrypt hash")
	}

	user := &models.User{
		Username:       "testuser",
		Name:           "Test User",
		HashedPassword: string(secret),
		Email:          "charleshuang233@gmail.com",
		Roles:          "user admin",
		GoogleID:       "123456789",
		Picture:        "https://example.com/avatar.png",
	}

	if err := db.Create(user).Error; err != nil {
		log.Fatal().Err(err).Msg("Failed to create user")
	}

	if err := storage.AddInvitation(db, "test_code", "user"); err != nil {
		log.Fatal().Err(err).Msg("Failed to add invitation")
	}
}
