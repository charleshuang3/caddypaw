package oidc

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"gorm.io/gorm"

	"github.com/charleshuang3/caddypaw/pkg/authn/storage"
)

type userInfoResponse struct {
	Sub     string `json:"sub"`
	Name    string `json:"name,omitempty"`
	Picture string `json:"picture,omitempty"`
	Roles   string `json:"roles,omitempty"`
	Email   string `json:"email,omitempty"`
}

// bearerScheme is the Authorization scheme of the UserInfo endpoint
// (RFC 6750 §2.1). Scheme names are case-insensitive (RFC 7235 §2.1).
const bearerScheme = "Bearer"

// writeUserInfoError writes the 401 carrying the WWW-Authenticate challenge
// required for Bearer token failures (RFC 6750 §3).
func writeUserInfoError(c *gin.Context, description string) {
	c.Header("WWW-Authenticate",
		`Bearer realm="oauth2/userinfo", error="invalid_token", error_description="`+description+`"`)
	c.String(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
}

// handleUserInfo implements the OIDC Core §5.3 UserInfo endpoint. It validates
// the Bearer access token and returns the user's claims, filtered by the
// scopes granted to the token.
func (o *OpenIDProvider) handleUserInfo(c *gin.Context) {
	scheme, accessToken, found := strings.Cut(c.GetHeader("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, bearerScheme) || accessToken == "" {
		writeUserInfoError(c, "missing bearer token")
		return
	}

	// Verify signature, expiry and issuer.
	token, err := jwt.Parse([]byte(accessToken), jwt.WithKey(jwa.RS256(), o.publicKey))
	if err != nil {
		writeUserInfoError(c, "invalid access token")
		return
	}

	if issuer, ok := token.Issuer(); !ok || issuer != o.config.Issuer {
		writeUserInfoError(c, "invalid issuer")
		return
	}

	subject, ok := token.Subject()
	if !ok || subject == "" {
		writeUserInfoError(c, "no subject")
		return
	}

	var scopeClaim string
	if err := token.Get("scope", &scopeClaim); err != nil {
		scopeClaim = ""
	}
	granted := strings.Split(scopeClaim, " ")

	hasScope := func(s string) bool {
		for _, it := range granted {
			if it == s {
				return true
			}
		}
		return false
	}

	// The subject of an access token is always the username
	// (genAccessToken), never the email address; looking users up by both
	// could return another account whose email equals this username.
	user, err := storage.GetUserByUsername(o.db, subject)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeUserInfoError(c, "unknown subject")
			return
		}
		logger.Error().Err(err).Msg("Database error during userinfo")
		c.String(http.StatusInternalServerError, "Database error")
		return
	}

	resp := &userInfoResponse{
		Sub: subject,
	}

	if hasScope("profile") {
		resp.Name = user.Name
		resp.Picture = user.Picture
		resp.Roles = user.Roles
	}

	if hasScope("email") {
		resp.Email = user.Email
	}

	c.JSON(http.StatusOK, resp)
}
