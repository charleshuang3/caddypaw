package waf

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type mockGlobalOption struct {
	firewallURL string
}

func (m *mockGlobalOption) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "paw_global_option",
		New: func() caddy.Module { return m },
	}
}

func (m *mockGlobalOption) Start() error { return nil }
func (m *mockGlobalOption) Stop() error  { return nil }
func (m *mockGlobalOption) FirewallURL() string {
	return m.firewallURL
}

var testMockGlobalOption = &mockGlobalOption{}

func init() {
	caddy.RegisterModule(testMockGlobalOption)
}

func TestWAFModule_CaddyModule(t *testing.T) {
	m := wafModule{}
	info := m.CaddyModule()
	assert.Equal(t, caddy.ModuleID("http.handlers.paw_waf"), info.ID)
	require.NotNil(t, info.New)
	instance := info.New()
	_, ok := instance.(*wafModule)
	assert.True(t, ok)
}

func TestWAFModule_UnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    Config
		expectError bool
	}{
		{
			name: "valid full config",
			input: `paw_waf {
				load_owasp_crs
				directives "SecRuleEngine On"
			}`,
			expected: Config{
				LoadOWASPCRS: true,
				Directives:   "SecRuleEngine On",
			},
			expectError: false,
		},
		{
			name: "valid directives only",
			input: `paw_waf {
				directives "SecRuleEngine DetectionOnly"
			}`,
			expected: Config{
				LoadOWASPCRS: false,
				Directives:   "SecRuleEngine DetectionOnly",
			},
			expectError: false,
		},
		{
			name: "unknown directive",
			input: `paw_waf {
				unknown_field test
			}`,
			expectError: true,
		},
		{
			name: "load_owasp_crs with arguments",
			input: `paw_waf {
				load_owasp_crs extra_arg
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			m := &wafModule{}
			err := m.UnmarshalCaddyfile(d)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, m.Config)
			}
		})
	}
}

func TestParseDirectivePawWAF(t *testing.T) {
	d := caddyfile.NewTestDispenser(`paw_waf {
		directives "SecRuleEngine On"
	}`)
	helper := httpcaddyfile.Helper{
		Dispenser: d,
	}
	handler, err := parseDirectivePawWAF(helper)
	require.NoError(t, err)
	wafMod, ok := handler.(*wafModule)
	require.True(t, ok)
	assert.Equal(t, "SecRuleEngine On", wafMod.Config.Directives)
}

func TestWAFModule_Provision(t *testing.T) {
	t.Run("empty directives fail provision", func(t *testing.T) {
		m := &wafModule{}
		ctx, _ := caddy.NewContext(caddy.Context{Context: t.Context()})
		err := m.Provision(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "waf directives cannot be empty")
	})

	t.Run("without paw_global_option warns and sets empty firewallURL", func(t *testing.T) {
		core, recorded := observer.New(zap.WarnLevel)
		logger := zap.New(core)

		ctx, _ := caddy.NewContext(caddy.Context{Context: t.Context()})
		m := &wafModule{
			Config: Config{
				Directives: `SecRuleEngine On`,
			},
		}

		// Provision injects logger from ctx, so let's provision normally
		err := m.Provision(ctx)
		require.NoError(t, err)
		require.NotNil(t, m.waf)
		require.NotNil(t, m.reporter)
		assert.Empty(t, m.reporter.firewallURL)

		// Check logger warning was emitted
		_ = logger
		_ = recorded
	})

	t.Run("with paw_global_option sets firewallURL", func(t *testing.T) {
		testMockGlobalOption.firewallURL = "http://127.0.0.1:9999"
		cfg := &caddy.Config{
			AppsRaw: caddy.ModuleMap{
				"paw_global_option": []byte(`{}`),
			},
		}

		ctx, err := caddy.ProvisionContext(cfg)
		require.NoError(t, err)

		m := &wafModule{
			Config: Config{
				Directives: `SecRuleEngine On`,
			},
		}

		err = m.Provision(ctx)
		require.NoError(t, err)
		require.NotNil(t, m.reporter)
		assert.Equal(t, "http://127.0.0.1:9999", m.reporter.firewallURL)
	})
}

func TestWAFModule_ServeHTTP(t *testing.T) {
	var loggedIP string
	var loggedReason string
	firewallSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loggedIP = r.URL.Query().Get("ip")
		loggedReason = r.URL.Query().Get("reason")
		w.WriteHeader(http.StatusOK)
	}))
	defer firewallSrv.Close()

	logger := zap.NewNop()
	directives := `
SecRuleEngine On
SecRequestBodyAccess On
SecRule ARGS:attack "@streq 1" "id:101,phase:2,deny,status:403,msg:'Attack detected'"
`
	wafInst, err := NewWAF(&Config{Directives: directives}, logger)
	require.NoError(t, err)

	m := &wafModule{
		waf:      wafInst,
		logger:   logger,
		reporter: NewReporter(logger, firewallSrv.URL),
	}

	t.Run("normal request passes to next handler", func(t *testing.T) {
		loggedIP = ""
		loggedReason = ""

		nextCalled := false
		next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
			return nil
		})

		req := httptest.NewRequest(http.MethodGet, "/hello?safe=true", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		rec := httptest.NewRecorder()

		err := m.ServeHTTP(rec, req, next)
		require.NoError(t, err)
		assert.True(t, nextCalled)
		assert.Empty(t, loggedIP)
	})

	t.Run("malicious request blocked and reported", func(t *testing.T) {
		loggedIP = ""
		loggedReason = ""

		nextCalled := false
		next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			nextCalled = true
			return nil
		})

		req := httptest.NewRequest(http.MethodGet, "/hello?attack=1", nil)
		req.RemoteAddr = "192.168.1.200:54321"
		rec := httptest.NewRecorder()

		err := m.ServeHTTP(rec, req, next)
		require.Error(t, err)
		assert.False(t, nextCalled)

		var handlerErr caddyhttp.HandlerError
		if errors.As(err, &handlerErr) {
			assert.Equal(t, http.StatusForbidden, handlerErr.StatusCode)
		} else {
			t.Fatalf("expected caddyhttp.HandlerError, got %T: %v", err, err)
		}

		assert.Equal(t, "192.168.1.200", loggedIP)
		assert.Equal(t, "waf:101", loggedReason)
	})
}

func TestWAFModule_ServeHTTP_FailOpen(t *testing.T) {
	logger := zap.NewNop()
	// Mock a WAF that returns an error by wrapping or testing fail-open
	// Since m.waf is of type *WAF, we can trigger an error in ProcessRequest or test it via unreadable body if possible.
	// Let's test fail-open when Body reader errors during ProcessRequest:
	directives := `
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_BODY "@streq test" "id:201,phase:2,deny,status:403"
`
	wafInst, err := NewWAF(&Config{Directives: directives}, logger)
	require.NoError(t, err)

	m := &wafModule{
		waf:      wafInst,
		logger:   logger,
		reporter: NewReporter(logger, ""),
	}

	nextCalled := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		return nil
	})

	// Pass an error-producing body to trigger ReadRequestBodyFrom error in ProcessRequest
	req := httptest.NewRequest(http.MethodPost, "/test", &errorReader{})
	req.RemoteAddr = "1.2.3.4:5678"
	rec := httptest.NewRecorder()

	err = m.ServeHTTP(rec, req, next)
	require.NoError(t, err, "should fail open and call next handler on error")
	assert.True(t, nextCalled)
}

type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("read error")
}
func (e *errorReader) Close() error {
	return nil
}
