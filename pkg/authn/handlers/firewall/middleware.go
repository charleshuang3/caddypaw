package firewall

import (
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	zlog "github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	fw "github.com/charleshuang3/caddypaw/pkg/firewall"
	"github.com/charleshuang3/caddypaw/pkg/firewall/gcplog"
	"github.com/charleshuang3/caddypaw/pkg/firewall/ipgeo"
	"github.com/charleshuang3/caddypaw/pkg/firewall/memory"
	"github.com/charleshuang3/caddypaw/pkg/firewall/opn"
	"github.com/charleshuang3/caddypaw/pkg/firewall/pf"
	"github.com/charleshuang3/caddypaw/pkg/firewall/ros"
	"github.com/charleshuang3/caddypaw/pkg/firewall/zerolog"
)

var (
	logger = log.With().Str("component", "firewall").Logger()
)

type ForgivableError struct {
	DurationInMinute uint `yaml:"duration_in_minute"`
	Count            uint `yaml:"count"`
}

type FirewallConfig struct {
	Provider         string          `yaml:"provider"`
	ProviderIP       string          `yaml:"provider_ip"`
	ProviderUser     string          `yaml:"provider_user"`
	ProviderPassword string          `yaml:"provider_password"`
	ListUUID         string          `yaml:"list_uuid"`
	BanMinutes       uint            `yaml:"ban_minutes"`
	Whitelist        []string        `yaml:"whitelist"`
	Forgivable       ForgivableError `yaml:"forgivable"`

	CityDBFile        string `yaml:"city_db_file"`
	UpdatedCityDBFile string `yaml:"updated_city_db_file"`
	ASNDBFile         string `yaml:"asn_db_file"`
	UpdatedASNDBFile  string `yaml:"updated_asn_db_file"`

	GoogleKeyFile   string `yaml:"google_key_file"`
	GoogleProjectID string `yaml:"google_project_id"`
}

var (
	// "memory" is a test-only provider: it records bans in memory instead of
	// touching a network device, and is intended for unit/E2E tests.
	supportedProviders = []string{"none", "memory", "ros", "opn", "pf"}
)

const (
	defaultBanMinutes       = 10
	defaultDurationInMinute = 10
	// defaultCount is a suspicion budget in points, not a number of events: one
	// independent signal costs 1 point, and a report carrying two corroborating
	// signals costs 2 (see the weight constants in pkg/caddypaw and pkg/waf). With
	// the historical count of 3 events, a plain violation therefore still bans on
	// the fourth report, while a corroborated one bans on the second.
	defaultCount = 3

	KeyHackingError = "HACKING_ERROR"
)

func (c *FirewallConfig) Validate() {
	if !slices.Contains(supportedProviders, c.Provider) {
		logger.Fatal().Msgf("Provider %s is not supported", c.Provider)
	}

	if c.Provider != "none" && c.Provider != "memory" {
		if c.ProviderIP == "" {
			logger.Fatal().Msg("ProviderIP is missing")
		}

		if c.ProviderUser == "" {
			logger.Fatal().Msg("ProviderUser is missing")
		}

		if c.ProviderPassword == "" {
			logger.Fatal().Msg("ProviderPassword is missing")
		}

		if c.Provider == "opn" && c.ListUUID == "" {
			logger.Fatal().Msg("ListUUID is missing")
		}
	}

	if c.CityDBFile == "" {
		logger.Fatal().Msg("CityDBFile is missing")
	}

	if c.UpdatedCityDBFile == "" {
		logger.Fatal().Msg("UpdatedCityDBFile is missing")
	}

	if c.ASNDBFile == "" {
		logger.Fatal().Msg("ASNDBFile is missing")
	}

	if c.UpdatedASNDBFile == "" {
		logger.Fatal().Msg("UpdatedASNDBFile is missing")
	}

	c.applyDefault()
}

func (c *FirewallConfig) applyDefault() {
	if c.BanMinutes == 0 {
		c.BanMinutes = defaultBanMinutes
	}

	if c.Forgivable.DurationInMinute == 0 {
		c.Forgivable.DurationInMinute = defaultDurationInMinute
	}

	if c.Forgivable.Count == 0 {
		c.Forgivable.Count = defaultCount
	}
}

type Firewall struct {
	fw   *fw.Firewall
	conf *FirewallConfig

	// memFW is non-nil only when provider is "memory". It records all ban
	// events in memory, mainly for tests and E2E assertions.
	memFW *memory.Firewall
}

// MemoryFirewall returns the underlying memory firewall when provider is
// "memory", otherwise nil.
func (f *Firewall) MemoryFirewall() *memory.Firewall {
	return f.memFW
}

func New(conf *FirewallConfig) *Firewall {
	f := &Firewall{}

	var firewallProvider fw.IFirewall
	switch conf.Provider {
	case "ros":
		firewallProvider = ros.New(
			conf.ProviderIP, conf.ProviderUser, conf.ProviderPassword)
	case "pf":
		firewallProvider = pf.New(
			conf.ProviderIP, conf.ProviderUser, conf.ProviderPassword)
	case "opn":
		firewallProvider = opn.New(
			conf.ProviderIP, conf.ProviderUser, conf.ProviderPassword, conf.ListUUID)
	case "memory":
		memFW := memory.New()
		f.memFW = memFW
		firewallProvider = memFW
	default:
		// keep firewallProvider nil which means no block on firewall
	}

	var fwlogger fw.ILogger
	if conf.GoogleKeyFile != "" {
		var err error
		fwlogger, err = gcplog.New(conf.GoogleKeyFile, conf.GoogleProjectID, "authn")
		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to create gcp logger")
		}
	} else {
		// fallback to local log if no google key file.
		fwlogger = zerolog.New(logger, zlog.InfoLevel, "authn")
	}

	mm, err := ipgeo.NewAutoUpdateMMIPGeo(
		conf.CityDBFile,
		conf.UpdatedCityDBFile,
		conf.ASNDBFile,
		conf.UpdatedASNDBFile)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create firewall middleware")
	}

	f.fw = fw.New(
		conf.Whitelist,
		firewallProvider,
		fwlogger,
		mm,
		fw.ForgivableError{
			Duration:    time.Duration(conf.Forgivable.DurationInMinute) * time.Minute,
			Count:       int(conf.Forgivable.Count),
			BanInMinute: int(conf.BanMinutes),
		})

	f.conf = conf
	return f
}

const (
	maxMetaHostLen   = 253
	maxMetaMethodLen = 16
	maxMetaPathLen   = 1024
)

func sanitizeMetaValue(s string, maxLen int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > maxLen {
		s = strings.ToValidUTF8(s[:maxLen], "")
	}
	return s
}

func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSpace(host))
	return sanitizeMetaValue(host, maxMetaHostLen)
}

func sanitizeRequestMeta(host, method, path string) fw.RequestMeta {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	return fw.RequestMeta{
		Host:   normalizeHost(host),
		Method: sanitizeMetaValue(strings.TrimSpace(method), maxMetaMethodLen),
		Path:   sanitizeMetaValue(path, maxMetaPathLen),
	}
}

func requestMetaFromGin(c *gin.Context) fw.RequestMeta {
	if c == nil || c.Request == nil {
		return fw.RequestMeta{}
	}
	var path string
	if c.Request.URL != nil {
		path = c.Request.URL.Path
	}
	return sanitizeRequestMeta(c.Request.Host, c.Request.Method, path)
}

func (f *Firewall) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// run handle
		c.Next()

		// after handler
		reason, ok := c.Get(KeyHackingError)
		if ok {
			ip := c.ClientIP()
			f.fw.LogIPErrorWithMeta(ip, reason.(string), fw.DefaultWeight, requestMetaFromGin(c))
			return
		}

		// this means user request to url undefined in router.
		if c.Writer.Status() == http.StatusNotFound {
			ip := c.ClientIP()
			f.fw.LogIPErrorWithMeta(ip, "undefined_url", fw.DefaultWeight, requestMetaFromGin(c))
			return
		}
	}
}
