package waf

import (
	"errors"
	"fmt"
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
	// Preset names a bundled rule configuration. Currently only "default"
	// is supported: it loads the recommended Coraza base config plus the
	// full embedded OWASP CRS. Mutually exclusive with directives.
	Preset       string `json:"preset,omitempty"`
	LoadOWASPCRS bool   `json:"load_owasp_crs,omitempty"`
	Directives   string `json:"directives,omitempty"`
}

// defaultPresetDirectives is the directives block applied by preset "default".
const defaultPresetDirectives = `Include @coraza.conf-recommended
SecRuleEngine On
Include @crs-setup.conf.example

# Relax inbound anomaly score threshold (default 5 is too strict for single false positives)
SecAction \
    "id:10000,\
    phase:1,\
    nolog,\
    pass,\
    setvar:tx.inbound_anomaly_score_threshold=10,\
    setvar:tx.outbound_anomaly_score_threshold=5"

# Allow text/plain in addition to default content types (used by Socket.IO / Engine.IO polling payloads)
SecAction \
    "id:10001,\
    phase:1,\
    nolog,\
    pass,\
    setvar:'tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/cloudevents+json| |text/plain|'"

# Exclude rule 930120 (OS File Access) on ARGS:scope for SSO callbacks (matches .profile in userinfo.profile)
SecRule REQUEST_URI "@rx ^/sso/.*callback" \
    "id:10002,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleRemoveTargetById=930120;ARGS:scope"

# Exclude rule 920420 (Content-Type enforcement) on /socket.io/ endpoints
SecRule REQUEST_URI "@beginsWith /socket.io/" \
    "id:10003,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleRemoveById=920420"

Include @owasp_crs/*.conf`

// UnmarshalCaddyfile parses the WAF configuration from a Caddyfile block.
func (c *Config) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "load_owasp_crs":
			if d.NextArg() {
				return d.ArgErr()
			}
			c.LoadOWASPCRS = true
		case "preset":
			if !d.NextArg() {
				return d.ArgErr()
			}
			c.Preset = d.Val()
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
	if c.Preset != "" {
		if c.Preset != "default" {
			return fmt.Errorf("unknown waf preset %q (supported: default)", c.Preset)
		}
		if strings.TrimSpace(c.Directives) != "" {
			return errors.New("waf preset and directives are mutually exclusive")
		}
		c.LoadOWASPCRS = true
		c.Directives = defaultPresetDirectives
	}
	if strings.TrimSpace(c.Directives) == "" {
		return errors.New("waf directives cannot be empty (use preset default or provide directives)")
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
