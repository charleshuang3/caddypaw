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

// Modes for Config.AfterAuth. They only take effect in paw_auth, where the
// authentication result is known; the standalone paw_waf directive always uses
// AfterAuthBlock.
const (
	// AfterAuthBlock is the default: the WAF runs before authentication and
	// blocks every offending request, authenticated or not. Omitting after_auth
	// also selects it.
	AfterAuthBlock = "block"
	// AfterAuthDetectOnly keeps inspecting authenticated requests but only
	// logs and reports matched rules; nothing is blocked.
	AfterAuthDetectOnly = "detect_only"
	// AfterAuthPhase1Only inspects only the URI and headers (phase 1) of
	// authenticated requests, skipping body inspection and buffering.
	AfterAuthPhase1Only = "phase1_only"
	// AfterAuthSkip disables WAF evaluation for authenticated requests.
	AfterAuthSkip = "skip"
)

// AfterAuthMode returns the effective post-authentication mode; an unset value
// means AfterAuthBlock. It is nil-safe, and it never rewrites AfterAuth, so the
// value the operator actually wrote stays visible in logs and adapted JSON.
func (c *Config) AfterAuthMode() string {
	if c == nil || c.AfterAuth == "" {
		return AfterAuthBlock
	}
	return c.AfterAuth
}

// Config holds the configuration for Coraza WAF.
type Config struct {
	// Preset names a bundled rule configuration. Currently only "default"
	// is supported: it loads the recommended Coraza base config plus the
	// full embedded OWASP CRS. Mutually exclusive with directives.
	Preset       string `json:"preset,omitempty"`
	LoadOWASPCRS bool   `json:"load_owasp_crs,omitempty"`
	Directives   string `json:"directives,omitempty"`
	// AfterAuth selects how paw_auth treats requests that authenticated
	// successfully. It is a runtime policy orthogonal to the rule set, so it
	// does not affect which rules are loaded. Empty means AfterAuthBlock; use
	// AfterAuthMode to read it.
	// Requests matching paw_auth's public_urls are always evaluated in blocking
	// mode, and requests that fail authentication are still inspected without
	// blocking, so that unauthenticated probing reaches /logerr.
	AfterAuth string `json:"after_auth,omitempty"`
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
		case "after_auth":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if d.NextArg() {
				return d.ArgErr()
			}
			c.AfterAuth = d.Val()
		default:
			return d.Errf("unrecognized waf directive '%s'", d.Val())
		}
	}
	return nil
}

// effectiveDirectives returns the directive block to compile, expanding Preset
// on the fly. It is a pure function: nothing is written back to the config.
//
// Expansion has to be derived rather than memoised because paw_auth builds two
// WAF instances from a single Config. Storing the expansion in Directives used to
// make the second instance see "preset and directives are mutually exclusive".
func (c *Config) effectiveDirectives() (string, error) {
	if c.Preset == "" {
		if strings.TrimSpace(c.Directives) == "" {
			return "", errors.New("waf directives cannot be empty (use preset default or provide directives)")
		}
		return c.Directives, nil
	}
	if c.Preset != "default" {
		return "", fmt.Errorf("unknown waf preset %q (supported: default)", c.Preset)
	}
	if strings.TrimSpace(c.Directives) != "" {
		return "", errors.New("waf preset and directives are mutually exclusive")
	}
	return defaultPresetDirectives, nil
}

// loadsOWASPCRS reports whether the embedded CRS filesystem must be mounted.
// The preset implies it; the explicit flag is the equivalent for raw directives.
func (c *Config) loadsOWASPCRS() bool {
	return c.Preset == "default" || c.LoadOWASPCRS
}

// Validate verifies that the configuration is valid. It is stateless: calling it
// any number of times is safe, which matters because Provision builds more than
// one WAF instance from the same Config.
func (c *Config) Validate() error {
	directives, err := c.effectiveDirectives()
	if err != nil {
		return err
	}
	if !c.loadsOWASPCRS() {
		for _, alias := range []string{"@owasp_crs", "@crs-setup", "@coraza.conf-recommended"} {
			if strings.Contains(directives, alias) {
				return errors.New("directives reference OWASP CRS rules but load_owasp_crs is false")
			}
		}
	}

	switch c.AfterAuthMode() {
	case AfterAuthBlock, AfterAuthDetectOnly, AfterAuthPhase1Only, AfterAuthSkip:
	default:
		return fmt.Errorf("unknown after_auth mode %q (supported: %s, %s, %s, %s)",
			c.AfterAuth, AfterAuthBlock, AfterAuthDetectOnly, AfterAuthPhase1Only, AfterAuthSkip)
	}
	return nil
}

// BuildCorazaConfig creates a coraza.WAFConfig configured with root FS, error logging, and directives.
func (c *Config) BuildCorazaConfig(logger *zap.Logger) (coraza.WAFConfig, error) {
	return c.buildCorazaConfig(logger, false)
}

// buildCorazaConfig is BuildCorazaConfig with an optional forced DetectionOnly
// rule engine.
func (c *Config) buildCorazaConfig(logger *zap.Logger, detectOnly bool) (coraza.WAFConfig, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	directives, err := c.effectiveDirectives()
	if err != nil {
		return nil, err
	}

	// Appending (not prepending) the engine override makes it win over any
	// SecRuleEngine directive inside the rule set.
	if detectOnly {
		directives += "\nSecRuleEngine DetectionOnly"
	}

	corazaCfg := coraza.NewWAFConfig().
		WithRequestBodyAccess()

	if c.loadsOWASPCRS() {
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

	corazaCfg = corazaCfg.WithDirectives(directives)
	return corazaCfg, nil
}
