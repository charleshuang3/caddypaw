package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestReporter_Report(t *testing.T) {
	var requestedURI atomic.Value
	var requestCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		requestedURI.Store(r.URL.RequestURI())
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	logger := zaptest.NewLogger(t)
	reporter := NewReporter(logger, srv.URL)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/login", nil)
	req.RemoteAddr = "192.168.1.100:54321"

	reporter.Report(req, "waf:949110")

	assert.Equal(t, int32(1), atomic.LoadInt32(&requestCount))
	val, ok := requestedURI.Load().(string)
	require.True(t, ok)
	assert.Contains(t, val, "/logerr?")
	assert.Contains(t, val, "ip=192.168.1.100")
	assert.Contains(t, val, "reason=waf%3A949110")
}

func TestReporter_ReportIP(t *testing.T) {
	var requestedURI atomic.Value
	var requestCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		requestedURI.Store(r.URL.RequestURI())
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	logger := zaptest.NewLogger(t)
	reporter := NewReporter(logger, srv.URL)

	reporter.ReportIP("10.0.0.5:1234", "waf:101")

	assert.Equal(t, int32(1), atomic.LoadInt32(&requestCount))
	val, ok := requestedURI.Load().(string)
	require.True(t, ok)
	assert.Contains(t, val, "ip=10.0.0.5")
	assert.Contains(t, val, "reason=waf%3A101")
}

func TestReporter_TrailingSlashTrimmed(t *testing.T) {
	var requestedURI atomic.Value

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedURI.Store(r.URL.RequestURI())
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	logger := zaptest.NewLogger(t)
	// Pass firewallURL with trailing slashes
	reporter := NewReporter(logger, srv.URL+"///")

	reporter.ReportIP("10.0.0.9", "waf:test")

	val, ok := requestedURI.Load().(string)
	require.True(t, ok)
	assert.True(t, strings.HasPrefix(val, "/logerr?"), "URI should start with /logerr?, got %s", val)
}

func TestReporter_EmptyFirewallURL(t *testing.T) {
	logger := zaptest.NewLogger(t)
	reporter := NewReporter(logger, "")

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "192.168.1.1:1234"

	// Should be a silent no-op and not panic
	reporter.Report(req, "waf:101")
	reporter.ReportIP("192.168.1.1", "waf:101")

	var nilReporter *Reporter
	nilReporter.Report(req, "waf:101")
	nilReporter.ReportIP("192.168.1.1", "waf:101")
}

func TestReporter_ServerErrorOrTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	logger := zaptest.NewLogger(t)
	reporter := NewReporter(logger, srv.URL)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "1.2.3.4:5678"

	// Should not panic on non-200 status
	reporter.Report(req, "waf:101")

	// Custom client with very low timeout to simulate failure
	client := &http.Client{Timeout: 1 * time.Millisecond}
	slowReporter := NewReporterWithClient(logger, "http://10.255.255.1:81", client)
	slowReporter.Report(req, "waf:101")
}
