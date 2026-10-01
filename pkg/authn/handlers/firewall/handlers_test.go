package firewall

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
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
