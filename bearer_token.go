package caddypaw

import (
	"fmt"
	"net/http"
	"strings"
)

func (a *authModule) checkBearerToken(w http.ResponseWriter, r *http.Request) (int, *userInfo, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return http.StatusUnauthorized, nil, fmt.Errorf("missing authorization header")
	}

	authParts := strings.Split(authHeader, " ")
	if len(authParts) != 2 || strings.ToLower(authParts[0]) != "bearer" {
		return http.StatusUnauthorized, nil, fmt.Errorf("invalid authorization header format")
	}

	token := authParts[1]
	if token != a.Token {
		return http.StatusUnauthorized, nil, fmt.Errorf("invalid token")
	}

	// For bearer token authentication, we don't have user info.
	// We can create a minimal user info if needed.
	user := &userInfo{}

	return http.StatusOK, user, nil
}
