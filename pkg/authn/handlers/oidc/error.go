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

// responseTokenError writes an RFC 6749 §5.2 JSON error response and logs the
// detailed message as a possible hacking attempt.
func responseTokenError(c *gin.Context, httpCode int, errCode, errMsg string) {
	logMayHack(c, errMsg)
	c.JSON(httpCode, &tokenErrorResponse{
		Error:            errCode,
		ErrorDescription: errMsg,
	})
}
