package firewall

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/charleshuang3/caddypaw/pkg/firewall"
	"github.com/charleshuang3/caddypaw/pkg/firewall/ipgeo"
)

func TestFirewallConfig_Validate(t *testing.T) {
	tests := []struct {
		name   string
		config FirewallConfig
	}{
		{
			name: "simple",
			config: FirewallConfig{
				Provider:          "ros",
				ProviderIP:        "192.168.1.1",
				ProviderUser:      "admin",
				ProviderPassword:  "password",
				CityDBFile:        "/path/to/city.mmdb",
				UpdatedCityDBFile: "/path/to/updated_city.mmdb",
				ASNDBFile:         "/path/to/asn.mmdb",
				UpdatedASNDBFile:  "/path/to/updated_asn.mmdb",
			},
		},
		{
			name: "full",
			config: FirewallConfig{
				Provider:         "ros",
				ProviderIP:       "192.168.1.1",
				ProviderUser:     "admin",
				ProviderPassword: "password",
				ListUUID:         "12345",
				Whitelist:        []string{"192.168.1.1", "192.168.1.2"},
				BanMinutes:       10,
				Forgivable: ForgivableError{
					DurationInMinute: 10,
					Count:            3,
				},

				CityDBFile:        "/path/to/city.mmdb",
				UpdatedCityDBFile: "/path/to/updated_city.mmdb",
				ASNDBFile:         "/path/to/asn.mmdb",
				UpdatedASNDBFile:  "/path/to/updated_asn.mmdb",

				GoogleKeyFile:   "/path/to/key.json",
				GoogleProjectID: "project-id",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.config.Validate()
		})
	}
}

func TestFirewallConfig_applyDefulat(t *testing.T) {
	tests := []struct {
		name           string
		config         FirewallConfig
		expectedConfig FirewallConfig
	}{
		{
			name: "apply defaults when values are zero",
			config: FirewallConfig{
				BanMinutes: 0,
				Forgivable: ForgivableError{
					DurationInMinute: 0,
					Count:            0,
				},
			},
			expectedConfig: FirewallConfig{
				BanMinutes: defaultBanMinutes,
				Forgivable: ForgivableError{
					DurationInMinute: defaultDurationInMinute,
					Count:            defaultCount,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.config.applyDefault()
			assert.Equal(t, tt.expectedConfig, tt.config)
		})
	}
}

// MockILogger is a mock implementation of ILogger for testing.
type MockILogger struct {
	logs []LogEntry
	wg   sync.WaitGroup
}

type LogEntry struct {
	IP     string
	action string
}

func (m *MockILogger) Log(ip string, jailUntil time.Time, reasons []string, action string, geo *ipgeo.IPGeo) {
	m.logs = append(m.logs, LogEntry{
		IP:     ip,
		action: action,
	})
	m.wg.Done()
}

func setupTestFirewall(t *testing.T) (*Firewall, *MockILogger) {
	t.Helper()
	config := &FirewallConfig{
		BanMinutes: 10,
	}
	logger := &MockILogger{}
	firewall := &Firewall{
		fw: firewall.New([]string{}, nil, logger, nil, firewall.ForgivableError{
			Duration:    time.Minute,
			Count:       3,
			BanInMinute: int(config.BanMinutes),
		}),
		conf: config,
	}
	return firewall, logger
}

func setupTestFirewallForMiddleware(t *testing.T) (*Firewall, *MockILogger, *gin.Engine) {
	t.Helper()

	fw, logger := setupTestFirewall(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	testGroup := router.Group("/")
	testGroup.Use(fw.Middleware())
	testGroup.GET("/ok", func(c *gin.Context) {})
	testGroup.GET("/contexterr", func(c *gin.Context) {
		c.Set(KeyHackingError, "a error")
	})
	testGroup.GET("/404", func(c *gin.Context) {
		c.Status(http.StatusNotFound)
	})
	testGroup.GET("/500", func(c *gin.Context) {
		// no action on firewall
		c.Status(http.StatusInternalServerError)
	})

	return fw, logger, router
}

func TestMiddleware_NoAction(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{
			name: "no error",
			path: "/ok",
		},
		{
			name: "500",
			path: "/500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, logger, router := setupTestFirewallForMiddleware(t)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)

			router.ServeHTTP(rec, req)

			// give some time if go func run.
			time.Sleep(time.Millisecond * 100)

			assert.Len(t, logger.logs, 0)
		})
	}
}

func TestMiddleware_LogErr(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{
			name: "404",
			path: "/404",
		},
		{
			name: "contexterr",
			path: "/contexterr",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, logger, router := setupTestFirewallForMiddleware(t)
			logger.wg.Add(1)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)

			router.ServeHTTP(rec, req)

			logger.wg.Wait()

			assert.Len(t, logger.logs, 1)
			assert.Equal(t, logger.logs[0].action, "count error")
		})
	}
}
