package waf

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestWAF_Phase2_NoBodyGET(t *testing.T) {
	cfg := &Config{
		Directives: `
SecRuleEngine On
SecRule ARGS:test "@streq attack" "id:101,phase:2,deny,status:403"
`,
	}

	logger := zaptest.NewLogger(t)
	wafEngine, err := NewWAF(cfg, logger)
	require.NoError(t, err)

	// Clean request
	cleanReq := httptest.NewRequest(http.MethodGet, "http://example.com/path?test=clean", http.NoBody)
	cleanReq.RemoteAddr = "1.2.3.4:12345"
	interrupted, status, ruleID, err := wafEngine.ProcessRequest(cleanReq)
	require.NoError(t, err)
	assert.False(t, interrupted)
	assert.Equal(t, 0, status)
	assert.Equal(t, 0, ruleID)

	// Attack request (no body GET)
	attackReq := httptest.NewRequest(http.MethodGet, "http://example.com/path?test=attack", http.NoBody)
	attackReq.RemoteAddr = "1.2.3.4:12345"
	interrupted, status, ruleID, err = wafEngine.ProcessRequest(attackReq)
	require.NoError(t, err)
	assert.True(t, interrupted)
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, 101, ruleID)
}

func TestWAF_PostBody_Refill(t *testing.T) {
	cfg := &Config{
		Directives: `
SecRuleEngine On
SecRequestBodyAccess On
SecRule ARGS:test "@streq clean" "id:102,phase:2,pass"
`,
	}

	logger := zaptest.NewLogger(t)
	wafEngine, err := NewWAF(cfg, logger)
	require.NoError(t, err)

	bodyPayload := `{"user": "alice", "data": "123456"}`
	req := httptest.NewRequest(http.MethodPost, "http://example.com/api", bytes.NewBufferString(bodyPayload))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "1.2.3.4:12345"

	interrupted, status, ruleID, err := wafEngine.ProcessRequest(req)
	require.NoError(t, err)
	assert.False(t, interrupted)
	assert.Equal(t, 0, status)
	assert.Equal(t, 0, ruleID)

	// Downstream read must be able to read full body
	readBytes, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, bodyPayload, string(readBytes))
}

func TestWAF_RequestBody_Intercept(t *testing.T) {
	cfg := &Config{
		Directives: `
SecRuleEngine On
SecRequestBodyAccess On
SecRule ARGS_POST:field "@contains evilpayload" "id:201,phase:2,deny,status:403"
`,
	}

	logger := zaptest.NewLogger(t)
	wafEngine, err := NewWAF(cfg, logger)
	require.NoError(t, err)

	bodyPayload := `field=this+contains+evilpayload+inside`
	req := httptest.NewRequest(http.MethodPost, "http://example.com/api", strings.NewReader(bodyPayload))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "1.2.3.4:12345"

	interrupted, status, ruleID, err := wafEngine.ProcessRequest(req)
	require.NoError(t, err)
	assert.True(t, interrupted)
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, 201, ruleID)
}

func TestWAF_OWASPCRS_StockConfig(t *testing.T) {
	cfg := &Config{
		LoadOWASPCRS: true,
		Directives: `
Include @coraza.conf-recommended
SecRuleEngine On
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
`,
	}

	logger := zaptest.NewLogger(t)
	wafEngine, err := NewWAF(cfg, logger)
	require.NoError(t, err)

	// SQLi attack in query string
	attackReq := httptest.NewRequest(http.MethodGet, "http://example.com/?q=1%20UNION%20SELECT%201,2,3--", http.NoBody)
	attackReq.RemoteAddr = "1.2.3.4:12345"
	interrupted, status, ruleID, err := wafEngine.ProcessRequest(attackReq)
	require.NoError(t, err)
	assert.True(t, interrupted)
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, 949110, ruleID)

	// Clean request
	cleanReq := httptest.NewRequest(http.MethodGet, "http://example.com/index.html", http.NoBody)
	cleanReq.RemoteAddr = "1.2.3.4:12345"
	interrupted, status, _, err = wafEngine.ProcessRequest(cleanReq)
	require.NoError(t, err)
	assert.False(t, interrupted)
	assert.Equal(t, 0, status)
}

func TestWAF_InterruptionStatusMapping(t *testing.T) {
	cfg := &Config{
		Directives: `
SecRuleEngine On
SecRule ARGS:act "@streq redirect" "id:301,phase:1,redirect:http://evil.com"
SecRule ARGS:act "@streq drop" "id:302,phase:1,drop,status:444"
SecRule ARGS:act "@streq deny_custom" "id:303,phase:1,deny,status:406"
`,
	}

	logger := zaptest.NewLogger(t)
	wafEngine, err := NewWAF(cfg, logger)
	require.NoError(t, err)

	// redirect -> status=403
	reqRedirect := httptest.NewRequest(http.MethodGet, "http://example.com/?act=redirect", http.NoBody)
	interrupted, status, ruleID, err := wafEngine.ProcessRequest(reqRedirect)
	require.NoError(t, err)
	assert.True(t, interrupted)
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, 301, ruleID)

	// drop with status:444 -> status=403
	reqDrop := httptest.NewRequest(http.MethodGet, "http://example.com/?act=drop", http.NoBody)
	interrupted, status, ruleID, err = wafEngine.ProcessRequest(reqDrop)
	require.NoError(t, err)
	assert.True(t, interrupted)
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, 302, ruleID)

	// deny with explicit status:406 -> status=406
	reqDeny := httptest.NewRequest(http.MethodGet, "http://example.com/?act=deny_custom", http.NoBody)
	interrupted, status, ruleID, err = wafEngine.ProcessRequest(reqDeny)
	require.NoError(t, err)
	assert.True(t, interrupted)
	assert.Equal(t, http.StatusNotAcceptable, status)
	assert.Equal(t, 303, ruleID)
}
