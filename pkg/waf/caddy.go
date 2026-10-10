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

// Provision sets up the module.
func (m *wafModule) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)

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
	interrupted, status, ruleID, err := m.waf.ProcessRequest(r)
	if err != nil {
		m.logger.Error("waf evaluation error; failing open", zap.Error(err))
		return next.ServeHTTP(w, r)
	}

	if interrupted {
		reason := fmt.Sprintf("waf:%d", ruleID)
		m.reporter.Report(r, reason)
		if status == 0 {
			status = http.StatusForbidden
		}
		return caddyhttp.Error(status, fmt.Errorf("waf rule %d triggered", ruleID))
	}

	return next.ServeHTTP(w, r)
}

var (
	_ caddy.Provisioner           = (*wafModule)(nil)
	_ caddy.Module                = (*wafModule)(nil)
	_ caddyhttp.MiddlewareHandler = (*wafModule)(nil)
	_ caddyfile.Unmarshaler       = (*wafModule)(nil)
)
