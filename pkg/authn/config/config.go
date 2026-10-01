package config

import (
	"net"
	"os"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/rs/zerolog/log"

	"github.com/charleshuang3/caddypaw/pkg/authn/gormw"
	middleware "github.com/charleshuang3/caddypaw/pkg/authn/handlers/firewall"
	"github.com/charleshuang3/caddypaw/pkg/authn/handlers/oidc"
)

var (
	logger = log.With().Str("component", "config").Logger()
)

type Config struct {
	Port            uint                      `yaml:"port"`
	BanHandlersPort uint                      `yaml:"ban_handlers_port"`
	GinMode         string                    `yaml:"gin_mode"`
	TrustedProxies  []string                  `yaml:"trusted_proxies"`
	OIDC            oidc.OIDCProviderConfig   `yaml:"oidc"`
	DB              gormw.Config              `yaml:"db"`
	Firewall        middleware.FirewallConfig `yaml:"firewall"`
}

func LoadConfig(path string) *Config {
	cfg := &Config{}

	file, err := os.Open(path)
	if err != nil {
		logger.Fatal().Err(err).Msgf("failed to open config file: %s", path)
	}
	defer func() {
		_ = file.Close()
	}()

	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(cfg); err != nil {
		logger.Fatal().Err(err).Msg("failed to decode config file")
	}

	cfg.validate()

	return cfg
}

// validateTrustedProxies rejects entries that are not a plain IP or CIDR, and
// the catch-all networks. Trusting every proxy makes the client IP spoofable
// through X-Forwarded-For, which feeds the firewall ban logic.
func (c *Config) validateTrustedProxies() {
	for _, proxy := range c.TrustedProxies {
		if strings.Contains(proxy, "/") {
			_, network, err := net.ParseCIDR(proxy)
			if err != nil {
				logger.Fatal().Msgf("TrustedProxies entry %q is not a valid IP or CIDR", proxy)
			}
			if ones, _ := network.Mask.Size(); ones == 0 {
				logger.Fatal().Msgf("TrustedProxies entry %q trusts every address", proxy)
			}
			continue
		}

		if net.ParseIP(proxy) == nil {
			logger.Fatal().Msgf("TrustedProxies entry %q is not a valid IP or CIDR", proxy)
		}
	}
}

func (c *Config) validate() {
	if c.Port == 0 {
		logger.Fatal().Msg("Port is missing")
	}

	if c.BanHandlersPort == 0 {
		logger.Fatal().Msg("BanHandlersPort is missing")
	}

	if c.GinMode == "" {
		logger.Fatal().Msg("GinMode is missing")
	}

	c.validateTrustedProxies()

	c.OIDC.Validate()

	c.Firewall.Validate()
}
