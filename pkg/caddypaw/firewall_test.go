package caddypaw

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/charleshuang3/caddypaw/pkg/caddypaw/config"
)

// TestAuthModule_logErr_UnreachableFirewall verifies that a firewall endpoint
// which cannot be reached is only logged: the response used to be closed
// unconditionally, which panicked on a nil response.
func TestAuthModule_logErr_UnreachableFirewall(t *testing.T) {
	a := &authModule{
		logger:      zap.NewNop(),
		authnConfig: &config.AuthnConfig{FirewallURL: "http://127.0.0.1:1"},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	assert.NotPanics(t, func() {
		a.logErr(req, "test reason")
	})
}
