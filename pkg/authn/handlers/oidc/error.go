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
