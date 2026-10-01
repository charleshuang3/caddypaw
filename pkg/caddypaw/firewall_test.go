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

// TestAuthModule_logErr_StripsPort verifies that the ip query parameter sent
// to the firewall endpoint is a bare IP without the port from RemoteAddr.
func TestAuthModule_logErr_StripsPort(t *testing.T) {
	var gotIP string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIP = r.URL.Query().Get("ip")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)

	oldClient := httpClient
	httpClient = ts.Client()
	t.Cleanup(func() { httpClient = oldClient })

	a := &authModule{
		logger:      zap.NewNop(),
		authnConfig: &config.AuthnConfig{FirewallURL: ts.URL},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:54321"

	a.logErr(req, "test reason")

	assert.Equal(t, "203.0.113.5", gotIP)
}
