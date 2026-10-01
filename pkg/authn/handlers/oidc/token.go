package oidc

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hashicorp/go-set/v3"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"gorm.io/gorm"

	"github.com/charleshuang3/caddypaw/pkg/authn/models"
	"github.com/charleshuang3/caddypaw/pkg/authn/storage"
)

// handleToken handles token requests for authorization code and refresh token grants.
func (o *OpenIDProvider) handleToken(c *gin.Context) {
	grantType := c.PostForm("grant_type")
	if grantType == "" {
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "require form value grant_type")
		return
	}

	switch grantType {
	case "authorization_code":
		o.handleTokenAuthorizationCode(c)
	case "refresh_token":
		o.handleTokenRefreshToken(c)
	default:
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Unsupported grant type")
	}
}

type handleTokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"` // seconds
	TokenType    string `json:"token_type"`
}

type handleTokenAuthorizationCodeParams struct {
	Code         string `form:"code" binding:"required"`
	ClientID     string `form:"client_id" binding:"required"`
	ClientSecret string `form:"client_secret" binding:"required"`
	// RedirectURI is optional for backward compatibility; when present it must
	// match the redirect_uri of the authorization request (RFC 6749 §4.1.3).
	RedirectURI string `form:"redirect_uri"`
}

func (o *OpenIDProvider) handleTokenAuthorizationCode(c *gin.Context) {
	params := &handleTokenAuthorizationCodeParams{}

	if err := c.ShouldBind(params); err != nil {
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Missing required parameters")
		return
	}

	authCode, ok := o.authCodeStorage.Get(params.Code)
	if !ok {
		// This should never happen unless the requester is cheating.
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Invalid authorization code")
		return
	}

	o.authCodeStorage.Delete(params.Code)

	if authCode.ClientID != params.ClientID {
		// This should never happen unless the requester is cheating.
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Invalid client ID")
		return
	}

	if params.RedirectURI != "" && params.RedirectURI != authCode.RedirectURI {
		// This should never happen unless the requester is cheating.
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Invalid redirect URI")
		return
	}

	// Fetch client from database using clientID
	client, err := storage.GetClientByID(o.db, params.ClientID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// This should never happen unless the requester is cheating.
			responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Client not found")
			return
		} else {
			logger.Error().Err(err).Msg("Failed to get client")
			c.String(http.StatusInternalServerError, "Database error")
			return
		}
	}

	if client.Secret != params.ClientSecret {
		// This should never happen unless the requester is cheating.
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Invalid client secret")
		return
	}

	user, err := storage.GetUserByID(o.db, authCode.UserID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.String(http.StatusUnauthorized, "Invalid user")
			return
		}
		logger.Error().Err(err).Msg("Database error during auth code token request")
		c.String(http.StatusInternalServerError, "Database error")
		return
	}

	// All valid we can gen tokens now.
	resp, err := o.genAllTokens(user, client, authCode.Scopes)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to gen tokens")
		c.String(http.StatusInternalServerError, "Failed to gen tokens")
		return
	}

	c.JSON(http.StatusOK, resp)
}

type handleTokenRefreshTokenParams struct {
	RefreshToken string `form:"refresh_token" binding:"required"`
	ClientID     string `form:"client_id" binding:"required"`
	ClientSecret string `form:"client_secret" binding:"required"`
}

func (o *OpenIDProvider) handleTokenRefreshToken(c *gin.Context) {
	params := &handleTokenRefreshTokenParams{}

	if err := c.ShouldBind(params); err != nil {
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Missing required parameters")
		return
	}

	refreshTokenParts := strings.Split(params.RefreshToken, ".")
	if len(refreshTokenParts) != 3 {
		// This should never happen unless the requester is cheating.
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Invalid refresh token: format")
		return
	}

	// Verify the token, this also check if the token is expired.
	verifiedToken, err := jwt.Parse([]byte(params.RefreshToken), jwt.WithKey(jwa.RS256(), o.publicKey))
	if err != nil {
		if errors.Is(err, jwt.TokenExpiredError()) {
			// let client re-auth
			c.String(http.StatusUnauthorized, "Invalid refresh token: expired")
			return
		}
		// This should never happen unless the requester is cheating.
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Invalid refresh token: signature")
		return
	}

	// Check token match request client
	aud, ok := verifiedToken.Audience()
	if !ok || !slices.Contains(aud, params.ClientID) {
		// This should never happen unless the requester is cheating.
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Invalid refresh token: audience")
		return
	}

	// Check token has exp field
	_, ok = verifiedToken.Expiration()
	if !ok {
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Invalid refresh token: no expiration")
		return
	}

	// Check issuer is this oidc provider
	iss, ok := verifiedToken.Issuer()
	if !ok || iss != o.config.Issuer {
		// This should never happen unless the requester is cheating.
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Invalid refresh token: issuer")
		return
	}

	// extract scopes
	var scopes string
	err = verifiedToken.Get("scope", &scopes)
	if err != nil {
		// This should never happen unless the requester is cheating.
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Invalid refresh token: scope")
		return
	}

	// Fetch refresh token from database
	refreshTokenSign := refreshTokenParts[2]
	refreshToken, err := storage.GetRefreshTokenBySign(o.db, refreshTokenSign)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Error().Err(err).Msg("Refresh token not found, private key leak?")
			responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Invalid refresh token: not found")
			return
		}
		logger.Error().Err(err).Msg("Database error during refresh token token request fetch refresh token")
		c.String(http.StatusInternalServerError, "Database error")
		return
	}

	if refreshToken.Revoked {
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Revoked refresh token")
		return
	}

	if refreshToken.Used {
		// Replay attack
		logger.Error().Msg("Replay attack detected")
		c.String(http.StatusBadRequest, "Used refresh token")
		return
	}

	// Fetch client from database using clientID
	client, err := storage.GetClientByID(o.db, params.ClientID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// This should never happen unless the requester is cheating.
			responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Client not found")
			return
		} else {
			logger.Error().Err(err).Msg("Failed to get client")
			c.String(http.StatusInternalServerError, "Database error")
			return
		}
	}

	if client.Secret != params.ClientSecret {
		// This should never happen unless the requester is cheating.
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Invalid client secret")
		return
	}

	user, err := storage.GetUserByID(o.db, refreshToken.UserID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.String(http.StatusUnauthorized, "Invalid user")
			return
		}
		logger.Error().Err(err).Msg("Database error during auth code token request")
		c.String(http.StatusInternalServerError, "Database error")
		return
	}

	// Mark the token used
	refreshToken.Used = true
	if err := storage.UpdateRefreshToken(o.db, refreshToken); err != nil {
		logger.Error().Err(err).Msg("Database error during refresh token token request update refresh token")
		c.String(http.StatusInternalServerError, "Database error")
		return
	}

	// All valid we can gen tokens
	resp, err := o.genAllTokens(user, client, strings.Split(scopes, " "))
	if err != nil {
		logger.Error().Err(err).Msg("Failed to gen tokens")
		c.String(http.StatusInternalServerError, "Failed to gen tokens")
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (o *OpenIDProvider) genAllTokens(user *models.User, client *models.Client, scopes []string) (*handleTokenResponse, error) {
	resp := &handleTokenResponse{
		Scope:     strings.Join(scopes, " "),
		ExpiresIn: client.AccessTokenTTL,
		TokenType: "Bearer",
	}

	accessToken, err := o.genAccessToken(user, client, scopes)
	if err != nil {
		return nil, err
	}

	resp.AccessToken = accessToken

	// gen refresh token only if scope includes "offline_access"
	if slices.Contains(scopes, "offline_access") {
		refreshToken, err := o.genRefreshToken(user, client, scopes)
		if err != nil {
			return nil, err
		}

		// save the sign part of refresh token to database
		refreshTokenSign := strings.Split(refreshToken, ".")[2]
		if err := storage.AddRefreshToken(o.db, &models.RefreshToken{
			Sign:      refreshTokenSign,
			UserID:    user.ID,
			Username:  user.Username,
			Client:    client.ClientName,
			ExpiresAt: time.Now().Add(client.RefreshTokenTTLDuration()),
		}); err != nil {
			return nil, err
		}

		resp.RefreshToken = refreshToken
	}

	// gen id token only if scope indudes "openid"
	if slices.Contains(scopes, "openid") {
		idToken, err := o.genIDToken(user, client, scopes)
		if err != nil {
			return nil, err
		}

		resp.IDToken = idToken
	}

	return resp, nil
}

func (o *OpenIDProvider) genAccessToken(user *models.User, client *models.Client, scopes []string) (string, error) {
	token, err := jwt.NewBuilder().
		Issuer(o.config.Issuer).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(client.AccessTokenTTLDuration())).
		Audience([]string{client.ClientID}).
		Subject(user.Username).
		Claim("roles", user.Roles).
		Claim("scope", strings.Join(scopes, " ")).
		Build()

	if err != nil {
		return "", fmt.Errorf("failed to build access token claims: %v", err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), o.privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %v", err)
	}

	return string(signed), nil
}

func (o *OpenIDProvider) genRefreshToken(user *models.User, client *models.Client, scopes []string) (string, error) {
	token, err := jwt.NewBuilder().
		Issuer(o.config.Issuer).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(client.RefreshTokenTTLDuration())).
		Audience([]string{client.ClientID}).
		Subject(user.Username).
		Claim("scope", strings.Join(scopes, " ")).
		Build()

	if err != nil {
		return "", fmt.Errorf("failed to build refresh token claims: %v", err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), o.privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign refresh token: %v", err)
	}

	return string(signed), nil
}

func (o *OpenIDProvider) genIDToken(user *models.User, client *models.Client, scopes []string) (string, error) {
	scopeSet := set.From(scopes)

	builder := jwt.NewBuilder().
		Issuer(o.config.Issuer).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(client.AccessTokenTTLDuration())).
		Audience([]string{client.ClientID}).
		Subject(user.Username).
		Claim("roles", user.Roles).
		Claim("scope", strings.Join(scopes, " "))

	if scopeSet.Contains("profile") {
		builder.
			Claim("name", user.Name).
			Claim("google_id", user.GoogleID).
			Claim("picture", user.Picture)
	}

	if scopeSet.Contains("email") {
		builder.Claim("email", user.Email)
	}

	token, err := builder.Build()

	if err != nil {
		return "", fmt.Errorf("failed to build id token claims: %v", err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), o.privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign id token: %v", err)
	}

	return string(signed), nil
}
