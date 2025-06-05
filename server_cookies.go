package caddypaw

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"bitbucket.org/creachadair/stringset"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

const (
	defaultCallbackURL = "/paw/callback"

	cookieKeyAccessToken  = "pwa_tok"
	cookieKeyRefreshToken = "pwa_ref"
)

func (a *AuthModule) checkServerCookies(w http.ResponseWriter, r *http.Request) (int, *userInfo, error) {
	path := r.URL.Path
	if path == defaultCallbackURL {
		return a.handleDefaultCallback(w, r)
	}

	accessToken, err := r.Cookie(cookieKeyAccessToken)
	// no access token, redirect user to auth
	if err != nil {
		return a.redirectToAuthorize(w, r)
	}

	u, err := a.validateJWT(accessToken.Value)
	if err != nil {
		if errors.Is(err, jwt.TokenExpiredError()) {
			return a.refreshToken(w, r)
		}
		// should log the err
		return http.StatusUnauthorized, nil, err
	}

	return http.StatusOK, u, nil
}

func (a *AuthModule) redirectToAuthorize(w http.ResponseWriter, r *http.Request) (int, *userInfo, error) {
	// save the url to state
	state := a.storeURLAndGenState(r.RequestURI)

	u := a.oauth2Config.AuthCodeURL(state)
	http.Redirect(w, r, u, http.StatusFound)

	return http.StatusFound, nil, nil
}

// handleDefaultCallback handles the callback from authn server
// 1. oauth2 code flow for tokens.
// 2. redirect the user to pre-auth url.
func (a *AuthModule) handleDefaultCallback(w http.ResponseWriter, r *http.Request) (int, *userInfo, error) {
	q := r.URL.Query()
	code := q.Get("code")
	if code == "" {
		return http.StatusBadRequest, nil, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("no code"))
	}
	state := q.Get("state")
	if state == "" {
		return http.StatusBadRequest, nil, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("no state"))
	}

	// state must be known
	redirect, ok := a.getAndDelState(state)
	if !ok {
		return http.StatusBadRequest, nil, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid state"))
	}

	// exchange code
	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, httpClient)
	tokens, err := a.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return http.StatusUnauthorized, nil, err
	}

	if err := setTokensToCookie(w, tokens); err != nil {
		return http.StatusInternalServerError, nil, err
	}

	http.Redirect(w, r, redirect, http.StatusFound)

	return http.StatusFound, nil, nil
}

// validateJWT verify the jwt token and return claims, any error except expiried should consider is a hack.
func (a *AuthModule) validateJWT(tok string) (*userInfo, error) {
	// jwt.Parse verify the signature, and check if the token is expired
	parsed, err := jwt.Parse([]byte(tok), jwt.WithKey(jwa.RS256(), a.publicKey))
	if err != nil {
		return nil, err
	}

	if issuer, ok := parsed.Issuer(); !ok || issuer != a.authnConfig.Issuer {
		a.logger.Error("invalid issuer", zap.String("issuer", issuer))
		return nil, fmt.Errorf("invalid issuer")
	}

	exp, _ := parsed.Expiration()

	userInfo := &userInfo{}

	userInfo.Expiration = exp.Unix()

	if aud, ok := parsed.Audience(); ok && len(aud) > 0 {
		if !slices.Contains(aud, a.ClientID) {
			return nil, fmt.Errorf("invalid audience")
		}
	} else {
		return nil, fmt.Errorf("no audience in token")
	}

	if sub, ok := parsed.Subject(); ok {
		userInfo.Username = sub
	} else {
		return nil, fmt.Errorf("no subject in token")
	}

	if err := parsed.Get("name", &userInfo.Name); err != nil {
		return nil, err
	}
	if err := parsed.Get("roles", &userInfo.Roles); err != nil {
		return nil, err
	}
	if err := parsed.Get("email", &userInfo.Email); err != nil {
		return nil, err
	}
	if err := parsed.Get("picture", &userInfo.Picture); err != nil {
		return nil, err
	}

	userInfo.roles = stringset.New(strings.Split(userInfo.Roles, " ")...)

	return userInfo, nil
}

func (a *AuthModule) refreshToken(w http.ResponseWriter, r *http.Request) (int, *userInfo, error) {
	refreshToken, err := r.Cookie(cookieKeyRefreshToken)
	if err != nil {
		// This may happen if user manually cleanup the refresh token
		return a.redirectToAuthorize(w, r)
	}

	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, httpClient)
	ts := a.oauth2Config.TokenSource(ctx, &oauth2.Token{
		RefreshToken: refreshToken.Value,
	})

	tokens, err := ts.Token()
	if err != nil {
		return http.StatusUnauthorized, nil, err
	}

	if err := setTokensToCookie(w, tokens); err != nil {
		return http.StatusInternalServerError, nil, err
	}

	rawIDToken, _ := tokens.Extra("id_token").(string)

	u, err := a.validateJWT(rawIDToken)
	if err != nil {
		// should log the err
		return http.StatusUnauthorized, nil, err
	}

	return http.StatusOK, u, nil
}

func setTokensToCookie(w http.ResponseWriter, tokens *oauth2.Token) error {
	rawIDToken, ok := tokens.Extra("id_token").(string)
	if !ok {
		return fmt.Errorf("no id_token in tokens")
	}

	if tokens.RefreshToken == "" {
		return fmt.Errorf("no refresh_token in tokens")
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieKeyAccessToken,
		Value:    rawIDToken,
		HttpOnly: true,
		Path:     "/",
	})

	http.SetCookie(w, &http.Cookie{
		Name:     cookieKeyRefreshToken,
		Value:    tokens.RefreshToken,
		HttpOnly: true,
		Path:     "/",
	})

	return nil
}
