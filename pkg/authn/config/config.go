package config

import (
	"os"

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

	c.OIDC.Validate()

	c.Firewall.Validate()
}
