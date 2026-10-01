package oidc

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
		responseTokenError(c, http.StatusBadRequest, "invalid_request", "require form value grant_type")
		return
	}

	switch grantType {
	case "authorization_code":
		o.handleTokenAuthorizationCode(c)
	case "refresh_token":
		o.handleTokenRefreshToken(c)
	default:
		responseTokenError(c, http.StatusBadRequest, "unsupported_grant_type", "Unsupported grant type")
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
	Code string `form:"code" binding:"required"`
	// RedirectURI is optional for backward compatibility; when present it must
	// match the redirect_uri of the authorization request (RFC 6749 §4.1.3).
	RedirectURI string `form:"redirect_uri"`
}

// clientCredentials are the credentials a client presented at the token
// endpoint, either as form values (client_secret_post) or in the Authorization
// header (client_secret_basic).
//
// RFC 6749 §2.3.1 requires the client id and secret to be form-urlencoded
// before they are put into the Authorization header. Clients disagree about
// it: golang.org/x/oauth2 escapes them, curl does not. Both spellings are
// therefore accepted, which is why each credential carries candidates.
type clientCredentials struct {
	clientIDs     []string
	clientSecrets []string
}

// credentialsFromForm reads client_secret_post credentials (RFC 6749 §2.3.1).
func credentialsFromForm(c *gin.Context) (clientCredentials, error) {
	clientID := c.PostForm("client_id")
	if clientID == "" {
		return clientCredentials{}, errors.New("missing client credentials")
	}

	clientSecret := c.PostForm("client_secret")
	if clientSecret == "" {
		return clientCredentials{}, errors.New("missing client_secret")
	}

	return clientCredentials{
		clientIDs:     []string{clientID},
		clientSecrets: []string{clientSecret},
	}, nil
}

// credentialsFromHeader reads client_secret_basic credentials.
func credentialsFromHeader(clientID, clientSecret string) clientCredentials {
	return clientCredentials{
		clientIDs:     spellings(clientID),
		clientSecrets: spellings(clientSecret),
	}
}

// spellings returns the accepted spellings of a value sent in the
// Authorization header: the value as sent, plus its form-urlencoded-decoded
// form when that differs.
func spellings(value string) []string {
	decoded, err := url.QueryUnescape(value)
	if err != nil || decoded == value {
		return []string{value}
	}
	return []string{value, decoded}
}

// matchClientID returns the spelling that is accepted as one of registered,
// which holds the client ids the credentials are expected to identify: the
// client id stored with the authorization code, or the audience of a refresh
// token.
func (cc clientCredentials) matchClientID(registered ...string) (string, bool) {
	for _, candidate := range cc.clientIDs {
		if slices.Contains(registered, candidate) {
			return candidate, true
		}
	}
	return "", false
}

// secretMatches reports whether any accepted spelling equals registered.
func (cc clientCredentials) secretMatches(registered ...string) bool {
	for _, candidate := range cc.clientSecrets {
		if slices.Contains(registered, candidate) {
			return true
		}
	}
	return false
}

// parseClientCredentials extracts the client credentials of a token request. HTTP
// Basic (RFC 6749 §2.3.1) takes precedence over form values; when both are
// present they must agree, otherwise the request is rejected.
func parseClientCredentials(c *gin.Context) (clientCredentials, error) {
	basicID, basicSecret, hasBasic := c.Request.BasicAuth()
	if !hasBasic {
		return credentialsFromForm(c)
	}

	credentials := credentialsFromHeader(basicID, basicSecret)

	// Form credentials may be present as well, in which case they must
	// describe the same client. A form without client_secret is ignored.
	if form, err := credentialsFromForm(c); err == nil {
		if _, ok := credentials.matchClientID(form.clientIDs...); !ok || !credentials.secretMatches(form.clientSecrets...) {
			return clientCredentials{}, errors.New("conflicting client credentials")
		}
	}

	return credentials, nil
}

func (o *OpenIDProvider) handleTokenAuthorizationCode(c *gin.Context) {
	params := &handleTokenAuthorizationCodeParams{}

	if err := c.ShouldBind(params); err != nil {
		responseTokenError(c, http.StatusBadRequest, "invalid_request", "Missing required parameters")
		return
	}

	credentials, err := parseClientCredentials(c)
	if err != nil {
		responseTokenError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	authCode, ok := o.authCodeStorage.Get(params.Code)
	if !ok {
		// This should never happen unless the requester is cheating.
		responseTokenError(c, http.StatusBadRequest, "invalid_grant", "Invalid authorization code")
		return
	}

	o.authCodeStorage.Delete(params.Code)

	clientID, ok := credentials.matchClientID(authCode.ClientID)
	if !ok {
		// This should never happen unless the requester is cheating.
		responseTokenError(c, http.StatusBadRequest, "invalid_grant", "Invalid client ID")
		return
	}

	if params.RedirectURI != "" && params.RedirectURI != authCode.RedirectURI {
		// This should never happen unless the requester is cheating.
		responseTokenError(c, http.StatusBadRequest, "invalid_grant", "Invalid redirect URI")
		return
	}

	// Fetch client from database using the client id stored with the auth code
	client, err := storage.GetClientByID(o.db, clientID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// This should never happen unless the requester is cheating.
			responseInvalidClient(c, "Client not found")
			return
		} else {
			logger.Error().Err(err).Msg("Failed to get client")
			responseTokenError(c, http.StatusInternalServerError, "temporarily_unavailable", "Database error")
			return
		}
	}

	if !credentials.secretMatches(client.Secret) {
		// This should never happen unless the requester is cheating.
		responseInvalidClient(c, "Invalid client secret")
		return
	}

	user, err := storage.GetUserByID(o.db, authCode.UserID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			responseTokenError(c, http.StatusBadRequest, "invalid_grant", "Invalid user")
			return
		}
		logger.Error().Err(err).Msg("Database error during auth code token request")
		responseTokenError(c, http.StatusInternalServerError, "temporarily_unavailable", "Database error")
		return
	}

	// All valid we can gen tokens now.
	resp, err := o.genAllTokens(user, client, authCode.Scopes, authCode.Nonce)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to gen tokens")
		responseTokenError(c, http.StatusInternalServerError, "temporarily_unavailable", "Failed to gen tokens")
		return
	}

	c.JSON(http.StatusOK, resp)
}

type handleTokenRefreshTokenParams struct {
	RefreshToken string `form:"refresh_token" binding:"required"`
}

func (o *OpenIDProvider) handleTokenRefreshToken(c *gin.Context) {
	params := &handleTokenRefreshTokenParams{}

	if err := c.ShouldBind(params); err != nil {
		responseTokenError(c, http.StatusBadRequest, "invalid_request", "Missing required parameters")
		return
	}

	credentials, err := parseClientCredentials(c)
	if err != nil {
		responseTokenError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	refreshTokenParts := strings.Split(params.RefreshToken, ".")
	if len(refreshTokenParts) != 3 {
		// This should never happen unless the requester is cheating.
		responseTokenError(c, http.StatusBadRequest, "invalid_grant", "Invalid refresh token: format")
		return
	}

	// Verify the token, this also check if the token is expired.
	verifiedToken, err := jwt.Parse([]byte(params.RefreshToken), jwt.WithKey(jwa.RS256(), o.publicKey))
	if err != nil {
		if errors.Is(err, jwt.TokenExpiredError()) {
			// An expired refresh token is expected (it happens whenever a user
			// comes back after the refresh token lifetime), so it must not be
			// counted as a hacking attempt. Let the client re-auth.
			responseTokenErrorExpected(c, http.StatusUnauthorized, "invalid_grant", "Invalid refresh token: expired")
			return
		}
		// This should never happen unless the requester is cheating.
		responseTokenError(c, http.StatusBadRequest, "invalid_grant", "Invalid refresh token: signature")
		return
	}

	// Check the credentials identify the client the token was issued to
	aud, _ := verifiedToken.Audience()
	clientID, ok := credentials.matchClientID(aud...)
	if !ok {
		// This should never happen unless the requester is cheating.
		responseTokenError(c, http.StatusBadRequest, "invalid_grant", "Invalid refresh token: audience")
		return
	}

	// Check token has exp field
	_, ok = verifiedToken.Expiration()
	if !ok {
		responseTokenError(c, http.StatusBadRequest, "invalid_grant", "Invalid refresh token: no expiration")
		return
	}

	// Check issuer is this oidc provider
	iss, ok := verifiedToken.Issuer()
	if !ok || iss != o.config.Issuer {
		// This should never happen unless the requester is cheating.
		responseTokenError(c, http.StatusBadRequest, "invalid_grant", "Invalid refresh token: issuer")
		return
	}

	// extract scopes
	var scopes string
	err = verifiedToken.Get("scope", &scopes)
	if err != nil {
		// This should never happen unless the requester is cheating.
		responseTokenError(c, http.StatusBadRequest, "invalid_grant", "Invalid refresh token: scope")
		return
	}

	// Fetch refresh token from database
	refreshTokenSign := refreshTokenParts[2]
	refreshToken, err := storage.GetRefreshTokenBySign(o.db, refreshTokenSign)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Error().Err(err).Msg("Refresh token not found, private key leak?")
			responseTokenError(c, http.StatusBadRequest, "invalid_grant", "Invalid refresh token: not found")
			return
		}
		logger.Error().Err(err).Msg("Database error during refresh token token request fetch refresh token")
		responseTokenError(c, http.StatusInternalServerError, "temporarily_unavailable", "Database error")
		return
	}

	if refreshToken.Revoked {
		responseTokenError(c, http.StatusBadRequest, "invalid_grant", "Revoked refresh token")
		return
	}

	if refreshToken.Used {
		// Replay attack
		logger.Error().Msg("Replay attack detected")
		responseTokenError(c, http.StatusBadRequest, "invalid_grant", "Used refresh token")
		return
	}

	// Fetch client from database using the client id the token was issued to
	client, err := storage.GetClientByID(o.db, clientID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// This should never happen unless the requester is cheating.
			responseInvalidClient(c, "Client not found")
			return
		} else {
			logger.Error().Err(err).Msg("Failed to get client")
			responseTokenError(c, http.StatusInternalServerError, "temporarily_unavailable", "Database error")
			return
		}
	}

	if !credentials.secretMatches(client.Secret) {
		// This should never happen unless the requester is cheating.
		responseInvalidClient(c, "Invalid client secret")
		return
	}

	user, err := storage.GetUserByID(o.db, refreshToken.UserID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			responseTokenError(c, http.StatusBadRequest, "invalid_grant", "Invalid user")
			return
		}
		logger.Error().Err(err).Msg("Database error during auth code token request")
		responseTokenError(c, http.StatusInternalServerError, "temporarily_unavailable", "Database error")
		return
	}

	// Mark the token used
	refreshToken.Used = true
	if err := storage.UpdateRefreshToken(o.db, refreshToken); err != nil {
		logger.Error().Err(err).Msg("Database error during refresh token token request update refresh token")
		responseTokenError(c, http.StatusInternalServerError, "temporarily_unavailable", "Database error")
		return
	}

	// All valid we can gen tokens
	resp, err := o.genAllTokens(user, client, strings.Split(scopes, " "), "")
	if err != nil {
		logger.Error().Err(err).Msg("Failed to gen tokens")
		responseTokenError(c, http.StatusInternalServerError, "temporarily_unavailable", "Failed to gen tokens")
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (o *OpenIDProvider) genAllTokens(user *models.User, client *models.Client, scopes []string, authNonce string) (*handleTokenResponse, error) {
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
		idToken, err := o.genIDToken(user, client, scopes, authNonce)
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

func (o *OpenIDProvider) genIDToken(user *models.User, client *models.Client, scopes []string, authNonce string) (string, error) {
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

	// Echo the nonce from the authorization request when present (OIDC Core
	// §3.1.3.7).
	if authNonce != "" {
		builder.Claim("nonce", authNonce)
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
