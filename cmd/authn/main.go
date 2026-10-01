package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-co-op/gocron/v2"
	"github.com/rs/zerolog/log"

	"github.com/charleshuang3/caddypaw/pkg/authn/config"
	"github.com/charleshuang3/caddypaw/pkg/authn/gormw"
	"github.com/charleshuang3/caddypaw/pkg/authn/handlers/firewall"
	"github.com/charleshuang3/caddypaw/pkg/authn/handlers/oidc"
	"github.com/charleshuang3/caddypaw/pkg/authn/handlers/statisfiles"
	"github.com/charleshuang3/caddypaw/pkg/authn/storage"
)

var (
	configPath = flag.String("c", os.Getenv("CONFIG_PATH"), "Path to configuration file")
)

func main() {
	flag.Parse()
	if *configPath == "" {
		log.Fatal().Msg("Config path must be provided via CONFIG_PATH env var or -c flag")
	}

	// Load configuration
	cfg := config.LoadConfig(*configPath)

	// cron schedule
	scheduler, _ := gocron.NewScheduler()
	scheduler.Start()

	// Initialize database
	db, err := gormw.Open(&cfg.DB)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to open database")
	}
	if err := db.Migrate(); err != nil {
		log.Fatal().Err(err).Msg("Failed to migrate database")
	}

	storage.RegisterRefreshTokensCleaner(scheduler, db)

	// Set up Gin router
	gin.SetMode(cfg.GinMode)
	// Trust no proxies: ClientIP() must never be spoofed via X-Forwarded-For,
	// as it feeds the firewall ban logic.
	router := gin.Default()
	// Trust no proxies: ClientIP() must never be spoofed via X-Forwarded-For,
	// as it feeds the firewall ban logic.
	if err := router.SetTrustedProxies(nil); err != nil {
		log.Fatal().Err(err).Msg("Failed to set trusted proxies")
	}

	// add CORS middleware
	router.Use(corsMiddleware())

	// add firewall middleware
	fw := firewall.New(&cfg.Firewall)
	router.Use(fw.Middleware())

	// Register OIDC handlers
	oidcProvider := oidc.NewOpenIDProvider(&cfg.OIDC, db)
	oidcProvider.RegisterHandlers(router.Group("/"))
	statisfiles.RegisterHandlers(router.Group("/"))

	oidcServer := startServer("oidc", cfg.Port, router)

	// firewall handler
	fwRouter := gin.Default()
	fw.RegisterHandlers(fwRouter.Group("/"))

	fwServer := startServer("firewall", cfg.BanHandlersPort, fwRouter)

	// Wait for interrupt signal to gracefully shutdown the server)

	c := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	// SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
	signal.Notify(c, os.Interrupt)

	// Block until we receive our signal.
	<-c

	// Create a deadline to wait for.
	wait := time.Second * 15
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	if err := oidcServer.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("oidcServer shutdown error")
	}

	if err := fwServer.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("fwServer shutdown error")
	}

	log.Info().Msg("shutting down")
	os.Exit(0)
}

func startServer(name string, port uint, handler http.Handler) *http.Server {
	// Start server
	srv := &http.Server{
		Addr: fmt.Sprintf(":%d", port),
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      handler,
	}

	// Run our server in a goroutine so that it doesn't block.
	go func() {
		log.Printf("start %s server at %q", name, srv.Addr)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatal().Err(err).Msg("Failed to start server")
		}
	}()

	return srv
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		}
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
