package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	middleware "github.com/charleshuang3/caddypaw/pkg/authn/handlers/firewall"
)

// firewallReports records the firewall report (KeyHackingError) of every
// request a test router handles, so tests can assert which failures are
// reported as possible hacking attempts.
type firewallReports struct {
	reasons []string
}

func (r *firewallReports) middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if reason, ok := c.Get(middleware.KeyHackingError); ok {
			r.reasons = append(r.reasons, reason.(string))
		}
	}
}

func TestResponseTokenError_FirewallReporting(t *testing.T) {
	newContext := func() *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "/oauth2/token", nil)
		return c
	}
	reportOf := func(c *gin.Context) any {
		return c.Keys[middleware.KeyHackingError]
	}

	t.Run("client error is reported", func(t *testing.T) {
		c := newContext()
		responseTokenError(c, http.StatusBadRequest, "invalid_grant", "Invalid authorization code")
		assert.Equal(t, " Invalid authorization code", reportOf(c))
	})

	t.Run("server error is not reported", func(t *testing.T) {
		c := newContext()
		responseTokenError(c, http.StatusInternalServerError, "temporarily_unavailable", "Database error")
		assert.Nil(t, reportOf(c))
	})

	t.Run("expected error is not reported", func(t *testing.T) {
		c := newContext()
		responseTokenErrorExpected(c, http.StatusUnauthorized, "invalid_grant", "Invalid refresh token: expired")
		assert.Nil(t, reportOf(c))
	})
}
