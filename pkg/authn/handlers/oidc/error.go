package oidc

import (
	"net/http"

	"github.com/gin-gonic/gin"

	middleware "github.com/charleshuang3/caddypaw/pkg/authn/handlers/firewall"
)

var (
	cleanedErrorMessage = true
)

func responseErrorAndLogMaybeHack(c *gin.Context, httpCode int, errMsg string) {
	logMayHack(c, errMsg)
	if cleanedErrorMessage {
		c.String(httpCode, http.StatusText(httpCode))
	} else {
		c.String(httpCode, errMsg)
	}
}

func logMayHack(c *gin.Context, errMsg string) {
	reason := c.FullPath() + " " + errMsg
	c.Set(middleware.KeyHackingError, reason)
}

// tokenErrorResponse is the RFC 6749 §5.2 error payload for the token endpoint.
type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// responseTokenError writes an RFC 6749 §5.2 JSON error response.
//
// Only client side failures (4xx) are logged as possible hacking attempts:
// 5xx responses are our own fault (database or signing failures) and must not
// count towards the firewall ban of the caller's IP.
func responseTokenError(c *gin.Context, httpCode int, errCode, errMsg string) {
	if httpCode < http.StatusInternalServerError {
		logMayHack(c, errMsg)
	}
	writeTokenError(c, httpCode, errCode, errMsg)
}

// responseTokenErrorExpected writes an RFC 6749 §5.2 JSON error response for
// a normal outcome of the protocol, such as an expired refresh token. The
// caller did nothing wrong, so it must never be reported to the firewall.
func responseTokenErrorExpected(c *gin.Context, httpCode int, errCode, errMsg string) {
	writeTokenError(c, httpCode, errCode, errMsg)
}

func writeTokenError(c *gin.Context, httpCode int, errCode, errMsg string) {
	c.JSON(httpCode, &tokenErrorResponse{
		Error:            errCode,
		ErrorDescription: errMsg,
	})
}
