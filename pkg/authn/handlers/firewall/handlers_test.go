package firewall

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fw "github.com/charleshuang3/caddypaw/pkg/firewall"
)

func setupTestFirewallForHandlers(t *testing.T) (*Firewall, *MockILogger, *gin.Engine) {
	t.Helper()

	fw, logger := setupTestFirewall(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	testGroup := router.Group("/")
	fw.RegisterHandlers(testGroup)

	return fw, logger, router
}

func TestHandlers(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		ip             string
		reason         string
		count          string
		weight         string
		expectedStatus int
		expectedLog    bool
		expectedAction string
	}{
		{
			name:           "ban success",
			path:           "/ban",
			ip:             "1.1.1.1",
			reason:         "test ban",
			expectedStatus: http.StatusOK,
			expectedLog:    true,
			expectedAction: "ban",
		},
		{
			name:           "ban missing ip",
			path:           "/ban",
			reason:         "test ban",
			expectedStatus: http.StatusBadRequest,
			expectedLog:    false,
			expectedAction: "",
		},
		{
			name:           "ban missing reason",
			path:           "/ban",
			ip:             "1.1.1.1",
			expectedStatus: http.StatusBadRequest,
			expectedLog:    false,
			expectedAction: "",
		},
		{
			name:           "logerr success",
			path:           "/logerr",
			ip:             "2.2.2.2",
			reason:         "test logerr",
			expectedStatus: http.StatusOK,
			expectedLog:    true,
			expectedAction: "count error",
		},
		{
			name:           "logerr missing ip",
			path:           "/logerr",
			reason:         "test logerr",
			expectedStatus: http.StatusBadRequest,
			expectedLog:    false,
			expectedAction: "",
		},
		{
			name:           "logerr missing reason",
			path:           "/logerr",
			ip:             "2.2.2.2",
			expectedStatus: http.StatusBadRequest,
			expectedLog:    false,
			expectedAction: "",
		},
		{
			name:           "logerr observed does not count",
			path:           "/logerr",
			ip:             "2.2.2.3",
			reason:         "waf:6001",
			count:          "false",
			expectedStatus: http.StatusOK,
			expectedLog:    true,
			expectedAction: "observed",
		},
		{
			name:           "logerr explicit count=true still counts",
			path:           "/logerr",
			ip:             "2.2.2.4",
			reason:         "waf:6001",
			count:          "true",
			expectedStatus: http.StatusOK,
			expectedLog:    true,
			expectedAction: "count error",
		},
		{
			name:           "logerr with weight is accepted",
			path:           "/logerr",
			ip:             "2.2.2.5",
			reason:         "waf:6001 | basic_auth: invalid credentials",
			weight:         "2",
			expectedStatus: http.StatusOK,
			expectedLog:    true,
			expectedAction: "count error",
		},
		{
			name:           "logerr with zero weight is rejected",
			path:           "/logerr",
			ip:             "2.2.2.6",
			reason:         "waf:6001",
			weight:         "0",
			expectedStatus: http.StatusBadRequest,
			expectedLog:    false,
			expectedAction: "",
		},
		{
			// The maximum a single request can produce is 2 (a refused request plus
			// a rejected password), so anything above it is a client bug or an
			// attempt to spend a whole budget with one call.
			name:           "logerr with oversize weight is rejected",
			path:           "/logerr",
			ip:             "2.2.2.7",
			reason:         "waf:6001",
			weight:         "3",
			expectedStatus: http.StatusBadRequest,
			expectedLog:    false,
			expectedAction: "",
		},
		{
			name:           "logerr ipv6 success",
			path:           "/logerr",
			ip:             "2001:db8::1",
			reason:         "test logerr",
			expectedStatus: http.StatusOK,
			expectedLog:    true,
			expectedAction: "count error",
		},
		{
			name:           "logerr invalid ip with port",
			path:           "/logerr",
			ip:             "2.2.2.2:54321",
			reason:         "test logerr",
			expectedStatus: http.StatusBadRequest,
			expectedLog:    false,
			expectedAction: "",
		},
		{
			name:           "logerr garbage ip",
			path:           "/logerr",
			ip:             "not-an-ip",
			reason:         "test logerr",
			expectedStatus: http.StatusBadRequest,
			expectedLog:    false,
			expectedAction: "",
		},
		{
			name:           "ban invalid ip",
			path:           "/ban",
			ip:             "not-an-ip",
			reason:         "test ban",
			expectedStatus: http.StatusBadRequest,
			expectedLog:    false,
			expectedAction: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, logger, router := setupTestFirewallForHandlers(t)

			rec := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, tt.path, nil)
			q := req.URL.Query()
			if tt.ip != "" {
				q.Add("ip", tt.ip)
			}
			if tt.reason != "" {
				q.Add("reason", tt.reason)
			}
			if tt.count != "" {
				q.Add("count", tt.count)
			}
			if tt.weight != "" {
				q.Add("weight", tt.weight)
			}
			req.URL.RawQuery = q.Encode()

			if tt.expectedLog {
				logger.wg.Add(1)
			}

			router.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)

			if tt.expectedLog {
				logger.wg.Wait()
				assert.Len(t, logger.logs, 1)
				assert.Equal(t, tt.ip, logger.logs[0].IP)
				assert.Equal(t, tt.expectedAction, logger.logs[0].action)
			} else {
				// give some time if go func run.
				time.Sleep(time.Millisecond * 100)
				assert.Len(t, logger.logs, 0)
			}
		})
	}
}

func TestLogerr_RequestMeta(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		method       string
		path         string
		count        string
		expectedMeta fw.RequestMeta
		expectedAct  string
	}{
		{
			name:         "counted event with host port and uppercase",
			host:         "Auth.Example.COM:8443",
			method:       "POST",
			path:         "/login",
			expectedMeta: fw.RequestMeta{Host: "auth.example.com", Method: "POST", Path: "/login"},
			expectedAct:  "count error",
		},
		{
			name:         "observed event with request meta",
			host:         "dav.example.com",
			method:       "PUT",
			path:         "/files/a",
			count:        "false",
			expectedMeta: fw.RequestMeta{Host: "dav.example.com", Method: "PUT", Path: "/files/a"},
			expectedAct:  "observed",
		},
		{
			name:         "backward compatible without meta",
			expectedMeta: fw.RequestMeta{},
			expectedAct:  "count error",
		},
		{
			name:         "sanitizes control chars, query string, and truncates long values",
			host:         "evil\n.example.com",
			method:       "GET\r\n" + strings.Repeat("X", 20),
			path:         "/" + strings.Repeat("p", maxMetaPathLen+50) + "?secret=1",
			expectedMeta: fw.RequestMeta{Host: "evil.example.com", Method: "GET" + strings.Repeat("X", maxMetaMethodLen-3), Path: "/" + strings.Repeat("p", maxMetaPathLen-1)},
			expectedAct:  "count error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, logger, router := setupTestFirewallForHandlers(t)

			var events []fw.Event
			var hookWg sync.WaitGroup
			hookWg.Add(1)
			f.fw.SetEventHook(func(ev fw.Event) {
				events = append(events, ev)
				hookWg.Done()
			})

			rec := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/logerr", nil)
			q := req.URL.Query()
			q.Add("ip", "2.2.2.10")
			q.Add("reason", "waf:949110")
			if tt.host != "" {
				q.Add("host", tt.host)
			}
			if tt.method != "" {
				q.Add("method", tt.method)
			}
			if tt.path != "" {
				q.Add("path", tt.path)
			}
			if tt.count != "" {
				q.Add("count", tt.count)
			}
			req.URL.RawQuery = q.Encode()

			logger.wg.Add(1)
			router.ServeHTTP(rec, req)
			logger.wg.Wait()
			hookWg.Wait()

			assert.Equal(t, http.StatusOK, rec.Code)
			require.Len(t, events, 1)
			assert.Equal(t, tt.expectedAct, events[0].Action)
			assert.Equal(t, tt.expectedMeta, events[0].Meta)
		})
	}
}
