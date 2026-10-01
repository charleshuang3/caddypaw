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

// handleUserInfo implements the OIDC Core §5.3 UserInfo endpoint. It validates
// the Bearer access token and returns the user's claims, filtered by the
// scopes granted to the token.
func (o *OpenIDProvider) handleUserInfo(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token", error_description="missing bearer token"`)
		c.String(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
		return
	}
	accessToken := strings.TrimPrefix(authHeader, prefix)

	// Verify signature, expiry and issuer.
	token, err := jwt.Parse([]byte(accessToken), jwt.WithKey(jwa.RS256(), o.publicKey))
	if err != nil {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token", error_description="invalid access token"`)
		c.String(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
		return
	}

	if issuer, ok := token.Issuer(); !ok || issuer != o.config.Issuer {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token", error_description="invalid issuer"`)
		c.String(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
		return
	}

	subject, ok := token.Subject()
	if !ok || subject == "" {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token", error_description="no subject"`)
		c.String(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
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

	user, err := storage.GetUserByUsernameOrEmail(o.db, subject)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.String(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
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
