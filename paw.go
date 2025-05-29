package caddypaw

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
	caddy.RegisterModule(Paw{})
	httpcaddyfile.RegisterHandlerDirective("paw", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	return Paw{}, nil
}

// Paw is a middleware module that prints messages before and after handling a request.
type Paw struct {
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Paw) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.paw",
		New: func() caddy.Module { return new(Paw) },
	}
}

// Provision sets up the module.
func (p *Paw) Provision(ctx caddy.Context) error {
	appModule, err := ctx.App(globalOptionAppName)
	if err != nil {
		return err
	}

	conf := appModule.(*globalOptionModule).AuthnConfig

	p.logger = ctx.Logger(p)
	p.logger.Info("authn in paw",
		zap.String("auth_url", conf.AuthURL),
		zap.String("token_url", conf.TokenURL),
	)

	return nil
}

// Validate ensures the module's configuration is valid.
func (p *Paw) Validate() error {
	// No validation needed for this simple example
	return nil
}

// ServeHTTP implements the caddyhttp.MiddlewareHandler interface.
func (p Paw) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	fmt.Println("before") // Print before handling the request

	// Wrap the response writer to capture the status code or intercept the response
	// For now, we just print "after" before calling the next handler's ServeHTTP,
	// which isn't exactly "after the server response" but rather "before the next handler".
	// To truly print *after* the proxied server responds, we'd need a more complex setup,
	// potentially involving wrapping the ResponseWriter or using a different hook point if available.
	// However, for this simple "before"/"after" requirement, this demonstrates the middleware concept.

	err := next.ServeHTTP(w, r) // Call the next handler in the chain

	fmt.Println("after") // Print after the next handler returns

	return err
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (p *Paw) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// No configuration options for this simple example
	// Just consume the directive name
	d.Next() // Consume directive name ("paw")
	if d.NextArg() {
		return d.ArgErr() // No arguments expected
	}
	return nil
}

var (
	// Interface guards
	_ caddy.Provisioner           = (*Paw)(nil)
	_ caddy.Validator             = (*Paw)(nil)
	_ caddyhttp.MiddlewareHandler = (*Paw)(nil)
	_ caddyfile.Unmarshaler       = (*Paw)(nil)
)
