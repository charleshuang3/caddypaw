package oidc

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"golang.org/x/oauth2"
	"gorm.io/gorm"

	"github.com/charleshuang3/caddypaw/pkg/authn/storage"
)

var (
	oauth2RequestClient = http.DefaultClient
)

type handleGoogleCallbackParams struct {
	Code  string `form:"code" binding:"required"`
	State string `form:"state" binding:"required"`
}

func (o *OpenIDProvider) handleGoogleCallback(c *gin.Context) {
	params := handleGoogleCallbackParams{}
	if err := c.ShouldBind(&params); err != nil {
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Missing required parameters")
		return
	}

	// 1. Check state in storage
	authState, ok := o.authStateStorage.Get(params.State)
	if !ok {
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Invalid state")
		return
	}
	// Remove state after use to prevent replay attacks
	o.authStateStorage.Delete(params.State)

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, oauth2RequestClient)

	// 2. Token exchange
	tok, err := o.config.SSO.Google.oauth2Config().Exchange(ctx, params.Code)
	if err != nil {
		// This should never happen unless the requester is cheating.
		logger.Error().Err(err).Msg("Failed to exchange token with Google")
		c.String(http.StatusBadRequest, "Token exchange failed")
		return
	}

	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok {
		logger.Error().Msg("No id_token field in oauth2 token")
		c.String(http.StatusBadRequest, "Invalid token response")
		return
	}

	// No need to verify the id token because we requested the token directly from Google.

	// 3. Extract email, name, picture from id token
	idToken, err := jwt.ParseInsecure([]byte(rawIDToken))
	if err != nil {
		logger.Error().Err(err).Msg("Failed to verify ID token")
		c.String(http.StatusBadRequest, "Invalid ID token")
		return
	}

	var email, picture, name string

	if err := idToken.Get("email", &email); err != nil {
		logger.Error().Err(err).Msg("Failed to extract email from ID token")
		c.String(http.StatusBadRequest, "Invalid ID token claims")
	}

	if err := idToken.Get("name", &name); err != nil {
		logger.Error().Err(err).Msg("Failed to extract name from ID token")
		c.String(http.StatusBadRequest, "Invalid ID token claims")
	}

	if err := idToken.Get("picture", &picture); err != nil {
		logger.Error().Err(err).Msg("Failed to extract picture from ID token")
		c.String(http.StatusBadRequest, "Invalid ID token claims")
	}

	// 4. Find if user in database, if not just respond with unregistered user message
	user, err := storage.GetUserByEmail(o.db, email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// User not registered, could redirect to registration page with pre-filled data
			o.render401(c, "User not registered")
			return
		}
		logger.Error().Err(err).Msg("Database error during Google login")
		c.String(http.StatusInternalServerError, "Database error")
		return
	}

	// 5. Check if name or picture in database needs update
	updated := false
	if user.Name != name {
		user.Name = name
		updated = true
	}
	if user.Picture != picture {
		user.Picture = picture
		updated = true
	}
	if updated {
		if err := o.db.Save(user).Error; err != nil {
			logger.Error().Err(err).Msg("Failed to update user data")
		}
	}

	// Successful login
	o.successfulLogin(params.State, authState, user, c)
}
