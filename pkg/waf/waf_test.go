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
	result, err := wafEngine.ProcessRequest(cleanReq)
	require.NoError(t, err)
	assert.False(t, result.Blocked)
	assert.Equal(t, 0, result.Status)
	assert.Equal(t, 0, result.RuleID)

	// Attack request (no body GET)
	attackReq := httptest.NewRequest(http.MethodGet, "http://example.com/path?test=attack", http.NoBody)
	attackReq.RemoteAddr = "1.2.3.4:12345"
	result, err = wafEngine.ProcessRequest(attackReq)
	require.NoError(t, err)
	assert.True(t, result.Blocked)
	assert.Equal(t, http.StatusForbidden, result.Status)
	assert.Equal(t, 101, result.RuleID)
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

	result, err := wafEngine.ProcessRequest(req)
	require.NoError(t, err)
	assert.False(t, result.Blocked)
	assert.Equal(t, 0, result.Status)
	assert.Equal(t, 0, result.RuleID)

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

	result, err := wafEngine.ProcessRequest(req)
	require.NoError(t, err)
	assert.True(t, result.Blocked)
	assert.Equal(t, http.StatusForbidden, result.Status)
	assert.Equal(t, 201, result.RuleID)
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
	result, err := wafEngine.ProcessRequest(attackReq)
	require.NoError(t, err)
	assert.True(t, result.Blocked)
	assert.Equal(t, http.StatusForbidden, result.Status)
	assert.Equal(t, 949110, result.RuleID)

	// Clean request
	cleanReq := httptest.NewRequest(http.MethodGet, "http://example.com/index.html", http.NoBody)
	cleanReq.RemoteAddr = "1.2.3.4:12345"
	result, err = wafEngine.ProcessRequest(cleanReq)
	require.NoError(t, err)
	assert.False(t, result.Blocked)
	assert.Equal(t, 0, result.Status)
}

func TestWAF_PresetDefault_TunedAllowances(t *testing.T) {
	cfg := &Config{
		Preset: "default",
	}

	logger := zaptest.NewLogger(t)
	wafEngine, err := NewWAF(cfg, logger)
	require.NoError(t, err)

	// 1. Google SSO Callback with scope containing .profile (must NOT trigger 930120 / 949110)
	ssoReq := httptest.NewRequest(http.MethodGet, "http://example.com/sso/google/callback?state=123&scope=email+profile+https://www.googleapis.com/auth/userinfo.profile", http.NoBody)
	ssoReq.RemoteAddr = "10.0.0.1:12345"
	result, err := wafEngine.ProcessRequest(ssoReq)
	require.NoError(t, err)
	assert.False(t, result.Blocked, "SSO callback should not be blocked")
	assert.Equal(t, 0, result.Status)
	assert.Equal(t, 0, result.RuleID)

	// 2. Socket.IO polling request with text/plain (must NOT trigger 920420 / 949110)
	socketReq := httptest.NewRequest(http.MethodPost, "http://example.com/socket.io/?EIO=4&transport=polling&sid=xyz", strings.NewReader("40"))
	socketReq.Header.Set("Content-Type", "text/plain;charset=UTF-8")
	socketReq.RemoteAddr = "10.0.0.1:12345"
	result, err = wafEngine.ProcessRequest(socketReq)
	require.NoError(t, err)
	assert.False(t, result.Blocked, "Socket.IO polling should not be blocked")
	assert.Equal(t, 0, result.Status)
	assert.Equal(t, 0, result.RuleID)

	// 3. Attack request is still blocked
	attackReq := httptest.NewRequest(http.MethodGet, "http://example.com/?q=1%20UNION%20SELECT%201,2,3--", http.NoBody)
	attackReq.RemoteAddr = "10.0.0.1:12345"
	result, err = wafEngine.ProcessRequest(attackReq)
	require.NoError(t, err)
	assert.True(t, result.Blocked, "SQLi attack must be blocked")
	assert.Equal(t, http.StatusForbidden, result.Status)
	assert.Equal(t, 949110, result.RuleID)
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
	result, err := wafEngine.ProcessRequest(reqRedirect)
	require.NoError(t, err)
	assert.True(t, result.Blocked)
	assert.Equal(t, http.StatusForbidden, result.Status)
	assert.Equal(t, 301, result.RuleID)

	// drop with status:444 -> status=403
	reqDrop := httptest.NewRequest(http.MethodGet, "http://example.com/?act=drop", http.NoBody)
	result, err = wafEngine.ProcessRequest(reqDrop)
	require.NoError(t, err)
	assert.True(t, result.Blocked)
	assert.Equal(t, http.StatusForbidden, result.Status)
	assert.Equal(t, 302, result.RuleID)

	// deny with explicit status:406 -> status=406
	reqDeny := httptest.NewRequest(http.MethodGet, "http://example.com/?act=deny_custom", http.NoBody)
	result, err = wafEngine.ProcessRequest(reqDeny)
	require.NoError(t, err)
	assert.True(t, result.Blocked)
	assert.Equal(t, http.StatusNotAcceptable, result.Status)
	assert.Equal(t, 303, result.RuleID)
}

func TestWAF_ProcessRequestPhase1_SkipsBody(t *testing.T) {
	cfg := &Config{
		Directives: `
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_URI "@contains header_attack" "id:401,phase:1,deny,status:403"
SecRule ARGS_POST:field "@contains body_attack" "id:402,phase:2,deny,status:403"
`,
	}

	logger := zaptest.NewLogger(t)
	wafEngine, err := NewWAF(cfg, logger)
	require.NoError(t, err)

	// A phase 2 attack in the body must not be detected, and the body must stay
	// fully readable downstream because nothing was buffered.
	bodyPayload := "field=body_attack"
	bodyReq := httptest.NewRequest(http.MethodPost, "http://example.com/dav/file", strings.NewReader(bodyPayload))
	bodyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bodyReq.RemoteAddr = "1.2.3.4:12345"

	result, err := wafEngine.ProcessRequestPhase1(bodyReq)
	require.NoError(t, err)
	assert.False(t, result.Blocked, "phase 1 must not evaluate the body")
	assert.Empty(t, result.Detected)

	readBytes, err := io.ReadAll(bodyReq.Body)
	require.NoError(t, err)
	assert.Equal(t, bodyPayload, string(readBytes))

	// Phase 1 attacks are still blocked.
	headerReq := httptest.NewRequest(http.MethodGet, "http://example.com/?q=header_attack", http.NoBody)
	headerReq.RemoteAddr = "1.2.3.4:12345"

	result, err = wafEngine.ProcessRequestPhase1(headerReq)
	require.NoError(t, err)
	assert.True(t, result.Blocked)
	assert.Equal(t, http.StatusForbidden, result.Status)
	assert.Equal(t, 401, result.RuleID)
	assert.Equal(t, 401, result.ReportRuleID())
	// The matched rules must survive an interruption too: callers that observe
	// instead of blocking (after_auth phase1_only and skip) rely on them.
	assert.Contains(t, result.Detected, 401)
}

func TestWAF_DetectOnly_ReportsWithoutBlocking(t *testing.T) {
	cfg := &Config{
		Directives: `
SecRuleEngine On
SecRequestBodyAccess On
SecRule ARGS:q "@contains attack" "id:501,phase:1,deny,status:403,log"
SecRule ARGS_POST:field "@contains attack" "id:502,phase:2,deny,status:403,log"
`,
	}

	logger := zaptest.NewLogger(t)
	wafEngine, err := NewWAFDetectOnly(cfg, logger)
	require.NoError(t, err)

	// The same rule blocks when the engine is not forced to DetectionOnly.
	blockingEngine, err := NewWAF(cfg, logger)
	require.NoError(t, err)

	t.Run("blocking engine still blocks the same request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/?q=attack", http.NoBody)
		req.RemoteAddr = "1.2.3.4:12345"

		result, err := blockingEngine.ProcessRequest(req)
		require.NoError(t, err)
		assert.True(t, result.Blocked)
	})

	t.Run("phase 1 match", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/?q=attack", http.NoBody)
		req.RemoteAddr = "1.2.3.4:12345"

		result, err := wafEngine.ProcessRequest(req)
		require.NoError(t, err)
		assert.False(t, result.Blocked, "detect-only must never block")
		assert.Contains(t, result.Detected, 501)
		assert.Equal(t, 501, result.ReportRuleID())
	})

	t.Run("phase 2 match keeps body readable", func(t *testing.T) {
		bodyPayload := "field=attack"
		req := httptest.NewRequest(http.MethodPost, "http://example.com/dav/file", strings.NewReader(bodyPayload))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "1.2.3.4:12345"

		result, err := wafEngine.ProcessRequest(req)
		require.NoError(t, err)
		assert.False(t, result.Blocked, "detect-only must never block")
		assert.Contains(t, result.Detected, 502)

		readBytes, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.Equal(t, bodyPayload, string(readBytes), "detect-only must not consume the body")
	})

	t.Run("clean request matches nothing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/?q=clean", http.NoBody)
		req.RemoteAddr = "1.2.3.4:12345"

		result, err := wafEngine.ProcessRequest(req)
		require.NoError(t, err)
		assert.False(t, result.Blocked)
		assert.Empty(t, result.Detected)
		assert.Equal(t, 0, result.ReportRuleID())
	})
}

func TestResult_ReportRuleID(t *testing.T) {
	tests := []struct {
		name   string
		result Result
		want   int
	}{
		{"nothing matched", Result{}, 0},
		{"interruption wins", Result{Blocked: true, RuleID: 7, Detected: []int{1, 2}}, 7},
		{"last detected rule", Result{Detected: []int{1, 2, 3}}, 3},
		{"blocked without rule id falls back to detected", Result{Blocked: true, Detected: []int{9}}, 9},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.result.ReportRuleID())
		})
	}
}

func TestWAF_DetectOnly_PresetDefault(t *testing.T) {
	cfg := &Config{Preset: "default"}

	logger := zaptest.NewLogger(t)
	wafEngine, err := NewWAFDetectOnly(cfg, logger)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/?q=1%20UNION%20SELECT%201,2,3--", http.NoBody)
	req.RemoteAddr = "1.2.3.4:12345"

	result, err := wafEngine.ProcessRequest(req)
	require.NoError(t, err)
	assert.False(t, result.Blocked, "detect-only must not block a CRS hit")
	require.NotEmpty(t, result.Detected)
	// The CRS closes with message-less tagging rules, so the reported ID must be
	// the anomaly aggregator rather than the literal last match.
	assert.Equal(t, 949110, result.ReportRuleID())
}
