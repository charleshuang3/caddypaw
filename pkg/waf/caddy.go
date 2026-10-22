package waf

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(wafModule{})
	httpcaddyfile.RegisterHandlerDirective("paw_waf", parseDirectivePawWAF)
	httpcaddyfile.RegisterDirectiveOrder("paw_waf", httpcaddyfile.Before, "reverse_proxy")
}

func parseDirectivePawWAF(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := &wafModule{}
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

type wafModule struct {
	Config Config `json:"config"`

	logger   *zap.Logger
	waf      *WAF
	reporter *Reporter
}

// CaddyModule returns the Caddy module information.
func (wafModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.paw_waf",
		New: func() caddy.Module { return new(wafModule) },
	}
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens.
func (m *wafModule) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name "paw_waf"
	return m.Config.UnmarshalCaddyfile(d)
}

// afterAuthIgnored reports the configured mode when it cannot take effect in this
// directive, together with whether it was set to something other than the default.
//
// after_auth depends on the authentication verdict, which only paw_auth knows.
// Ignoring the option silently in paw_waf would leave the operator believing the
// WAF is relaxed when it is not. AfterAuthMode is used so that an omitted value
// and the explicit "block" spelling are both correctly treated as the default
// rather than triggering a bogus warning.
func (m *wafModule) afterAuthIgnored() (string, bool) {
	mode := m.Config.AfterAuthMode()
	if mode == AfterAuthBlock {
		return "", false
	}
	return mode, true
}

// Provision sets up the module.
func (m *wafModule) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)

	if mode, ignored := m.afterAuthIgnored(); ignored {
		m.logger.Warn("waf: after_auth is ignored by the standalone paw_waf directive; "+
			"it only takes effect inside a paw_auth waf block, and paw_waf always blocks",
			zap.String("after_auth", mode))
	}

	var firewallURL string
	if app, err := ctx.AppIfConfigured("paw_global_option"); err == nil && app != nil {
		if p, ok := app.(FirewallURLProvider); ok {
			firewallURL = p.FirewallURL()
		}
	} else {
		m.logger.Warn("paw_global_option not configured; WAF violations will not be reported")
	}

	m.reporter = NewReporter(m.logger, firewallURL)

	var err error
	m.waf, err = NewWAF(&m.Config, m.logger)
	if err != nil {
		return fmt.Errorf("initializing waf: %w", err)
	}

	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *wafModule) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	result, err := m.waf.ProcessRequest(r)
	if err != nil {
		m.logger.Error("waf evaluation error; failing open", zap.Error(err))
		return next.ServeHTTP(w, r)
	}

	if result.Blocked {
		status := result.Status
		if status == 0 {
			status = http.StatusForbidden
		}
		m.reporter.Report(r, fmt.Sprintf("waf:%d", result.RuleID), WeightBlocked)
		return caddyhttp.Error(status, fmt.Errorf("waf rule %d triggered", result.RuleID))
	}

	return next.ServeHTTP(w, r)
}

var (
	_ caddy.Provisioner           = (*wafModule)(nil)
	_ caddy.Module                = (*wafModule)(nil)
	_ caddyhttp.MiddlewareHandler = (*wafModule)(nil)
	_ caddyfile.Unmarshaler       = (*wafModule)(nil)
)
