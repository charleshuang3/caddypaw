package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-co-op/gocron/v2"
	"github.com/rs/zerolog/log"

	"github.com/charleshuang3/caddypaw/pkg/authn/config"
	"github.com/charleshuang3/caddypaw/pkg/authn/gormw"
	"github.com/charleshuang3/caddypaw/pkg/authn/handlers/dashboard"
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
	router := newRouter(cfg.TrustedProxies)

	// add CORS middleware
	router.Use(corsMiddleware())

	// add firewall middleware
	fw := firewall.New(&cfg.Firewall)
	var eventRecorder *storage.SecurityEventRecorder
	if cfg.Dashboard.IsEnabled() {
		eventRecorder = storage.NewSecurityEventRecorder(db, 0)
		fw.SetEventHook(eventRecorder.Record)
		storage.RegisterSecurityEventsCleaner(scheduler, db, cfg.Dashboard.RetentionDays)
	}
	router.Use(fw.Middleware())

	// Register OIDC handlers
	oidcProvider := oidc.NewOpenIDProvider(&cfg.OIDC, db)
	oidcProvider.RegisterHandlers(router.Group("/"))
	statisfiles.RegisterHandlers(router.Group("/"))

	oidcServer := startServer("oidc", cfg.Port, router)

	// firewall handler
	fwRouter := newRouter(cfg.TrustedProxies)
	fw.RegisterHandlers(fwRouter.Group("/"))
	if cfg.Dashboard.IsEnabled() {
		dashHandler := dashboard.New(db, defaultWebUIDir(cfg.Dashboard.WebUIDir))
		dashHandler.RegisterHandlers(fwRouter.Group("/"))
		dashHandler.RegisterStatic(fwRouter)
	}

	fwServer := startServer("firewall", cfg.BanHandlersPort, fwRouter)

	// Wait for interrupt signal to gracefully shutdown the server)

	c := make(chan os.Signal, 1)
	// Accept graceful shutdowns on SIGINT (Ctrl+C) and SIGTERM (docker stop / systemd).
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

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

	if eventRecorder != nil {
		flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer flushCancel()
		if err := eventRecorder.Close(flushCtx); err != nil {
			log.Error().Err(err).Msg("security event recorder close error")
		}
	}

	log.Info().Msg("shutting down")
	os.Exit(0)
}

// defaultWebUIDir returns the configured WebUI directory if non-empty, or falls
// back to a built WebUI directory under the working directory (./webui/dist
// locally, ./webui in the Docker image) or alongside the binary. Directories
// containing package.json are skipped so the unbuilt Vite source tree is never
// auto-selected.
func defaultWebUIDir(configured string) string {
	if configured != "" {
		return configured
	}
	candidates := []string{"./webui/dist", "./webui"}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "webui"))
	}
	for _, candidate := range candidates {
		if isBuiltWebUIDir(candidate) {
			log.Info().Str("webui_dir", candidate).Msg("Auto-detected WebUI directory")
			return candidate
		}
	}
	log.Info().Msg("No built WebUI directory found; static serving disabled")
	return ""
}

func isBuiltWebUIDir(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	indexInfo, err := os.Stat(filepath.Join(dir, "index.html"))
	if err != nil || indexInfo.IsDir() {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "package.json")); err == nil {
		return false
	}
	return true
}

// newRouter builds a gin engine for every authn HTTP server.
//
// gin trusts every proxy by default, which makes ClientIP() spoofable through
// X-Forwarded-For; ClientIP() feeds the firewall ban logic, so an attacker
// could report errors for arbitrary IPs. Only proxies listed in
// trusted_proxies are trusted, and an empty list (the default) trusts nobody.
func newRouter(trustedProxies []string) *gin.Engine {
	router := gin.Default()
	if err := router.SetTrustedProxies(trustedProxies); err != nil {
		log.Fatal().Err(err).Msg("Failed to set trusted proxies")
	}

	return router
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
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
