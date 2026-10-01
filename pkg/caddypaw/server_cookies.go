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

func (a *authModule) checkServerCookies(w http.ResponseWriter, r *http.Request) (int, *userInfo, error) {
	path := r.URL.Path
	if path == defaultCallbackURL {
		return a.handleDefaultCallback(w, r)
	}

	accessToken, err := r.Cookie(cookieKeyAccessToken)
	// no access token, redirect user to auth
	if err != nil {
		a.logger.Info("no access token, redirecting to authorize", zap.String("path", path))
		return a.redirectToAuthorize(w, r)
	}

	u, err := a.validateJWT(accessToken.Value)
	if err != nil {
		if errors.Is(err, jwt.TokenExpiredError()) {
			return a.refreshToken(w, r)
		}
		a.logErr(r, fmt.Sprintf("invalid token on path: %s", path))
		return http.StatusUnauthorized, nil, err
	}

	return http.StatusOK, u, nil
}

func (a *authModule) redirectToAuthorize(w http.ResponseWriter, r *http.Request) (int, *userInfo, error) {
	// save the url to state
	state := a.storeURLAndGenState(r.RequestURI)

	u := a.oauth2Config.AuthCodeURL(state)

	if a.isAjax(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return http.StatusUnauthorized, nil, nil
	}

	http.Redirect(w, r, u, http.StatusFound)

	return http.StatusFound, nil, nil
}

// classifyTokenError reports whether a failed token endpoint call means the
// user has to authenticate again.
//
// Only invalid_grant (the code or refresh token expired, was already used, or
// belongs to another client) means the grant is gone. Other 4xx responses are
// gateway misconfiguration (invalid_client, invalid_request) and 5xx, 429 and
// network failures mean authn is unavailable; restarting the auth flow for any
// of them would only loop or amplify the load.
func classifyTokenError(err error) bool {
	var retrieveErr *oauth2.RetrieveError
	if !errors.As(err, &retrieveErr) {
		// Non-HTTP errors (connection refused, timeouts, ...) are
		// infrastructure failures.
		return false
	}

	return retrieveErr.ErrorCode == "invalid_grant"
}

// handleDefaultCallback handles the callback from authn server
// 1. oauth2 code flow for tokens.
// 2. redirect the user to pre-auth url.
func (a *authModule) handleDefaultCallback(w http.ResponseWriter, r *http.Request) (int, *userInfo, error) {
	q := r.URL.Query()

	// An authorize request can be rejected before any code is issued: the authn
	// server then redirects back here with the standard OAuth2 error
	// parameters (RFC 6749 §4.1.2.1). Report it and let the client retry; this
	// is not an attack, so it must not reach the firewall, and there is no new
	// auth flow to start (which could loop).
	if authErr := q.Get("error"); authErr != "" {
		description := q.Get("error_description")
		a.logger.Error("authorize request rejected by authn",
			zap.String("error", authErr), zap.String("error_description", description))
		return http.StatusBadRequest, nil, caddyhttp.Error(http.StatusBadRequest,
			fmt.Errorf("authorization error: %s: %s", authErr, description))
	}

	code := q.Get("code")
	if code == "" {
		a.logErr(r, "callback: no auth code")
		return http.StatusBadRequest, nil, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("no code"))
	}
	state := q.Get("state")
	if state == "" {
		a.logErr(r, "callback: no state")
		return http.StatusBadRequest, nil, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("no state"))
	}

	// state must be known
	redirect, ok := a.getAndDelState(state)
	if !ok {
		// State not found: may have expired, been evicted from cache, or is a replay.
		// Redirect to a fresh auth flow rather than returning a 400, which could
		// cause a redirect loop if the error handler sends the user back here.
		a.logErr(r, "callback: unknown state, restarting auth flow")
		a.logger.Info("callback: unknown state, redirecting to authorize", zap.String("state", state))
		return a.redirectToAuthorize(w, r)
	}

	// exchange code
	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, httpClient)
	tokens, err := a.oauth2Config.Exchange(ctx, code)
	if err != nil {
		if !classifyTokenError(err) {
			a.logger.Error("token exchange failed with server error", zap.Error(err))
			return http.StatusBadGateway, nil, err
		}
		// The grant is gone; the user has to authenticate again. Do not redirect
		// from here: the browser already sits on the callback URL, and a
		// persistently failing exchange would loop.
		a.logger.Info("token exchange failed, the client must authenticate again", zap.Error(err))
		return http.StatusUnauthorized, nil, err
	}

	if err := setTokensToCookie(w, tokens); err != nil {
		return http.StatusInternalServerError, nil, err
	}

	http.Redirect(w, r, redirect, http.StatusFound)

	return http.StatusFound, nil, nil
}

// validateJWT verify the jwt token and return claims, any error except expiried should consider is a hack.
func (a *authModule) validateJWT(tok string) (*userInfo, error) {
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

func (a *authModule) refreshToken(w http.ResponseWriter, r *http.Request) (int, *userInfo, error) {
	refreshToken, err := r.Cookie(cookieKeyRefreshToken)
	if err != nil {
		// This may happen if user manually cleanup the refresh token
		a.logger.Info("no refresh token, redirecting to authorize", zap.String("path", r.URL.Path))
		return a.redirectToAuthorize(w, r)
	}

	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, httpClient)
	ts := a.oauth2Config.TokenSource(ctx, &oauth2.Token{
		RefreshToken: refreshToken.Value,
	})

	tokens, err := ts.Token()
	if err != nil {
		if !classifyTokenError(err) {
			a.logger.Error("token refresh failed with server error", zap.Error(err), zap.String("path", r.URL.Path))
			return http.StatusBadGateway, nil, err
		}
		// This may happen if refresh token also expired.
		a.logger.Info("refresh token exchange failed, redirecting to authorize", zap.Error(err), zap.String("path", r.URL.Path))
		return a.redirectToAuthorize(w, r)
	}

	if err := setTokensToCookie(w, tokens); err != nil {
		return http.StatusInternalServerError, nil, err
	}

	rawIDToken, _ := tokens.Extra("id_token").(string)

	u, err := a.validateJWT(rawIDToken)
	if err != nil {
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
