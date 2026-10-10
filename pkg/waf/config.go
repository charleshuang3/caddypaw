package waf

import (
	"errors"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/jcchavezs/mergefs"
	mergefsio "github.com/jcchavezs/mergefs/io"
	"go.uber.org/zap"
)

// Config holds the configuration for Coraza WAF.
type Config struct {
	LoadOWASPCRS bool   `json:"load_owasp_crs,omitempty"`
	Directives   string `json:"directives,omitempty"`
}

// UnmarshalCaddyfile parses the WAF configuration from a Caddyfile block.
func (c *Config) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "load_owasp_crs":
			if d.NextArg() {
				return d.ArgErr()
			}
			c.LoadOWASPCRS = true
		case "directives":
			if !d.NextArg() {
				return d.ArgErr()
			}
			c.Directives = d.Val()
		default:
			return d.Errf("unrecognized waf directive '%s'", d.Val())
		}
	}
	return nil
}

// Validate verifies that the configuration is valid.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.Directives) == "" {
		return errors.New("waf directives cannot be empty")
	}
	if !c.LoadOWASPCRS {
		for _, alias := range []string{"@owasp_crs", "@crs-setup", "@coraza.conf-recommended"} {
			if strings.Contains(c.Directives, alias) {
				return errors.New("directives reference OWASP CRS rules but load_owasp_crs is false")
			}
		}
	}
	return nil
}

// BuildCorazaConfig creates a coraza.WAFConfig configured with root FS, error logging, and directives.
func (c *Config) BuildCorazaConfig(logger *zap.Logger) (coraza.WAFConfig, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	corazaCfg := coraza.NewWAFConfig().
		WithRequestBodyAccess()

	if c.LoadOWASPCRS {
		corazaCfg = corazaCfg.WithRootFS(mergefs.Merge(coreruleset.FS, mergefsio.OSFS))
	}

	if logger != nil {
		corazaCfg = corazaCfg.WithErrorCallback(func(rule types.MatchedRule) {
			logger.Warn("coraza rule match",
				zap.Int("rule_id", rule.Rule().ID()),
				zap.String("msg", rule.Message()),
				zap.String("data", rule.Data()),
				zap.String("uri", rule.URI()),
				zap.String("client_ip", rule.ClientIPAddress()),
			)
		})
	}

	corazaCfg = corazaCfg.WithDirectives(c.Directives)
	return corazaCfg, nil
}
