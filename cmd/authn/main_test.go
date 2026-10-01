package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// clientIPFrom returns the client IP resolved by a router built with the given
// trusted proxies for a request from remoteAddr carrying X-Forwarded-For.
func clientIPFrom(trustedProxies []string, remoteAddr, forwardedFor string) string {
	router := newRouter(trustedProxies)
	router.GET("/client-ip", func(c *gin.Context) {
		c.String(http.StatusOK, c.ClientIP())
	})

	req := httptest.NewRequest(http.MethodGet, "/client-ip", nil)
	req.RemoteAddr = remoteAddr
	req.Header.Set("X-Forwarded-For", forwardedFor)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	return rec.Body.String()
}

func TestNewRouter_TrustsNoProxyByDefault(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// gin's default trusted proxy list is 0.0.0.0/0, which would return the
	// spoofed X-Forwarded-For value instead of the real remote address.
	assert.Equal(t, "203.0.113.5",
		clientIPFrom(nil, "203.0.113.5:54321", "1.2.3.4"))
}

func TestNewRouter_TrustsConfiguredProxy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	assert.Equal(t, "1.2.3.4",
		clientIPFrom([]string{"203.0.113.0/24"}, "203.0.113.5:54321", "1.2.3.4"))
}
