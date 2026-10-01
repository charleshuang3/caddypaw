package testapp

import (
	"context"
	_ "embed"
	"fmt"
	"html/template"
	"net/http"
	"time"
	"uuid"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

const (
	testClientID = "test-client-id"
	testSecret   = "test-client-secret"

	accessTokenKey  = "access"
	refreshTokenKey = "refresh"
)

var (
	//go:embed testapp.html
	tmplContent string
	tmpl        *template.Template
)

type templateData struct {
	AccessTokenSubject  string
	AccessTokenEmail    string
	AccessTokenExpiry   string
	RawAccessToken      string
	RefreshTokenSubject string
	RefreshTokenExpiry  string
	RawRefreshToken     string
}

func init() {
	var err error
	tmpl, err = template.New("testapp").Parse(tmplContent)
	if err != nil {
		panic(err)
	}
}

func NewServer(port int) {
	// Set up Gin router
	gin.SetMode("debug")
	router := gin.Default()

	oidcProvider, err := oidc.NewProvider(context.Background(), "http://127.0.0.1:8081/oauth2")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create OIDC provider")
	}

	oauth2Config := &oauth2.Config{
		ClientID:     testClientID,
		ClientSecret: testSecret,
		RedirectURL:  "http://127.0.0.1:8082/callback",
		Endpoint:     oidcProvider.Endpoint(),
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
	}

	h := &handler{
		oidcProvider: oidcProvider,
		oauth2Config: oauth2Config,
		states:       map[string]string{},
	}
	router.GET("/cleancookies", h.cleanCookies)
	router.GET("/refreshtoken", h.refreshToken)
	router.GET("/callback", h.handleCallback)
	router.GET("/", h.index)
	router.GET("/test", h.handle)
	if err := router.Run(fmt.Sprintf(":%d", port)); err != nil {
		log.Fatal().Err(err).Msg("Failed to run router")
	}
}

type handler struct {
	oidcProvider *oidc.Provider
	oauth2Config *oauth2.Config
	states       map[string]string // state -> redirect
}

func (h *handler) index(c *gin.Context) {
	c.Redirect(http.StatusFound, "/test")
}

func (h *handler) handle(c *gin.Context) {
	ctx := context.Background()

	needLogin := false
	needRefresh := false

	aTokenInfo := &idTokenInfo{}
	rTokenInfo := &refreshTokenInfo{}

	accessToken, err := c.Cookie(accessTokenKey)
	if err != nil {
		log.Info().Msg("No access token, need login")
		needLogin = true
	} else {
		func() {
			// validate the token
			v := h.oidcProvider.Verifier(&oidc.Config{
				ClientID:        testClientID,
				SkipExpiryCheck: true,
			})
			tok, err := v.Verify(ctx, accessToken)
			if err != nil {
				log.Info().Err(err).Msg("Invalid access token, need login")
				needLogin = true
				return
			}

			if err := aTokenInfo.readIDToken(tok); err != nil {
				log.Info().Err(err).Msg("Extract access token failed, need login")
				needLogin = true
				return
			}

			if tok.Expiry.Before(time.Now()) {
				log.Info().Msg("Access token expired, need refresh")
				needRefresh = true
			}
		}()
	}

	refreshToken, err := c.Cookie(refreshTokenKey)
	if err != nil {
		log.Info().Msg("No refresh token, need login")
		needLogin = true
	} else {
		func() {
			// validate the token
			v := h.oidcProvider.Verifier(&oidc.Config{
				ClientID:        testClientID,
				SkipExpiryCheck: true,
			})
			tok, err := v.Verify(ctx, refreshToken)
			if err != nil {
				log.Info().Err(err).Msg("Invalid refresh token, need login")
				needLogin = true
				return
			}

			if err := rTokenInfo.readRefreshToken(tok); err != nil {
				log.Info().Err(err).Msg("Extract refresh token failed, need login")
				needLogin = true
				return
			}

			if tok.Expiry.Before(time.Now()) {
				log.Info().Msg("Refresh token expired, need login")
				needLogin = true
			}
		}()
	}

	if needLogin {
		state := uuid.New().String()
		h.states[state] = c.Request.URL.String()
		c.Redirect(http.StatusFound, h.oauth2Config.AuthCodeURL(state))
		return
	}

	if needRefresh {
		ts := h.oauth2Config.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
		toks, err := ts.Token()
		if err != nil {
			log.Info().Err(err).Msg("Refresh token failed")
			c.String(http.StatusInternalServerError, "Refresh token failed")
			return
		}
		rawIDToken, ok := toks.Extra("id_token").(string)
		if !ok {
			log.Error().Msg("No id_token field in oauth2 token")
			c.String(http.StatusInternalServerError, "No id_token field in oauth2 token")
			return
		}

		c.SetCookie(accessTokenKey, rawIDToken, toks.Expiry.Second(), "/", "127.0.0.1", false, true)
		// Note: Not all OIDC providers issue a new refresh token. If toks.RefreshToken is empty, the old one is still valid.
		if toks.RefreshToken != "" {
			c.SetCookie(refreshTokenKey, toks.RefreshToken, 0, "/", "127.0.0.1", false, true)
		}
		c.Redirect(http.StatusFound, c.Request.RequestURI)
		return
	}

	accessTokenExp := ""
	if aTokenInfo.ExpiresAt != 0 {
		expiryTime := time.Unix(aTokenInfo.ExpiresAt, 0)
		accessTokenExp = fmt.Sprintf("%d seconds left", int(time.Until(expiryTime).Seconds()))
	}
	refreshTokenExp := ""
	if rTokenInfo.ExpiresAt != 0 {
		expiryTime := time.Unix(rTokenInfo.ExpiresAt, 0)
		refreshTokenExp = fmt.Sprintf("%d seconds left", int(time.Until(expiryTime).Seconds()))
	}

	data := templateData{
		AccessTokenSubject:  aTokenInfo.Subject,
		AccessTokenEmail:    aTokenInfo.Email,
		AccessTokenExpiry:   accessTokenExp,
		RawAccessToken:      accessToken,
		RefreshTokenSubject: rTokenInfo.Subject,
		RefreshTokenExpiry:  refreshTokenExp,
		RawRefreshToken:     refreshToken,
	}

	c.Writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	err = tmpl.Execute(c.Writer, data)
	if err != nil {
		log.Error().Err(err).Msg("Failed to execute template")
		c.String(http.StatusInternalServerError, "Failed to execute template")
		return
	}
}

func (h *handler) refreshToken(c *gin.Context) {
	ctx := context.Background()
	refreshToken, err := c.Cookie(refreshTokenKey)
	if err != nil {
		log.Info().Msg("No refresh token in cookie for refreshToken endpoint")
		c.String(http.StatusUnauthorized, "Refresh token not found")
		return
	}

	ts := h.oauth2Config.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	toks, err := ts.Token()
	if err != nil {
		log.Error().Err(err).Msg("Failed to refresh token")
		c.String(http.StatusInternalServerError, "Failed to refresh token")
		return
	}

	rawIDToken, ok := toks.Extra("id_token").(string)
	if !ok {
		log.Error().Msg("No id_token field in oauth2 token")
		c.String(http.StatusInternalServerError, "No id_token field in oauth2 token")
		return
	}

	c.SetCookie(accessTokenKey, rawIDToken, toks.Expiry.Second(), "/", "127.0.0.1", false, true)
	// Note: Not all OIDC providers issue a new refresh token. If toks.RefreshToken is empty, the old one is still valid.
	if toks.RefreshToken != "" {
		c.SetCookie(refreshTokenKey, toks.RefreshToken, 0, "/", "127.0.0.1", false, true)
	}

	c.Status(http.StatusOK)
}

func (h *handler) handleCallback(c *gin.Context) {
	ctx := context.Background()
	state := c.Query("state")
	code := c.Query("code")

	redirectURL, ok := h.states[state]
	if !ok {
		log.Error().Msg("Invalid state parameter")
		c.String(http.StatusBadRequest, "Invalid state parameter")
		return
	}
	delete(h.states, state) // consume the state

	oauth2Token, err := h.oauth2Config.Exchange(ctx, code)
	if err != nil {
		log.Error().Err(err).Msg("Failed to exchange token")
		c.String(http.StatusInternalServerError, "Failed to exchange token: "+err.Error())
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		log.Error().Msg("No id_token field in oauth2 token")
		c.String(http.StatusInternalServerError, "No id_token field in oauth2 token")
		return
	}

	verifier := h.oidcProvider.Verifier(&oidc.Config{ClientID: testClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Error().Err(err).Msg("Failed to verify ID Token")
		c.String(http.StatusInternalServerError, "Failed to verify ID Token: "+err.Error())
		return
	}

	// Store tokens in cookies
	// For simplicity in this test app, we'll use the raw ID token string as the "access token"
	// and the OAuth2 refresh token as the "refresh token".
	c.SetCookie(accessTokenKey, rawIDToken, int(time.Until(idToken.Expiry).Seconds()), "/", "127.0.0.1", false, true)
	if oauth2Token.RefreshToken != "" {
		c.SetCookie(refreshTokenKey, oauth2Token.RefreshToken, 0, "/", "127.0.0.1", false, true) // 0 for session cookie or a long expiry
	}

	c.Redirect(http.StatusFound, redirectURL)
}

func (h *handler) cleanCookies(c *gin.Context) {
	c.SetCookie(accessTokenKey, "", -1, "/", "127.0.0.1", false, true)
	c.SetCookie(refreshTokenKey, "", -1, "/", "127.0.0.1", false, true)
	c.String(http.StatusOK, "Cookies cleaned")
}
