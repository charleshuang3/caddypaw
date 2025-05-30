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
	caddy.RegisterModule(Auth{})
	httpcaddyfile.RegisterHandlerDirective("paw_auth", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	return &Auth{}, nil
}

// Auth is a middleware module that handles authentication and authorization.
type Auth struct {
	logger *zap.Logger

	ClientID     string   `json:"client_id,omitempty"`
	ClientSecret string   `json:"client_secret,omitempty"`
	Roles        []string `json:"roles,omitempty"`
	CallbackURL  string   `json:"callback_url,omitempty"`
	PublicURLs   []string `json:"public_urls,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Auth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.paw_auth",
		New: func() caddy.Module { return new(Auth) },
	}
}

// Provision sets up the module.
func (p *Auth) Provision(ctx caddy.Context) error {
	appModule, err := ctx.App(globalOptionAppName)
	if err != nil {
		return err
	}

	conf := appModule.(*globalOptionModule).AuthnConfig

	p.logger = ctx.Logger(p)
	p.logger.Info("authn in paw_auth",
		zap.String("auth_url", conf.AuthURL),
		zap.String("token_url", conf.TokenURL),
	)

	return nil
}

// Validate ensures the module's configuration is valid.
func (p *Auth) Validate() error {
	if p.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	if p.ClientSecret == "" {
		return fmt.Errorf("client_secret is required")
	}
	if len(p.Roles) == 0 {
		return fmt.Errorf("roles are required")
	}
	return nil
}

// ServeHTTP implements the caddyhttp.MiddlewareHandler interface.
func (p *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
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
func (p *Auth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// the caddyfile config:
	// paw_auth {
	//   client_id the-client-id
	//   client_secret the-client-secret
	//   roles role1 role2
	//   callback_url callback-url # optional
	//   public_urls url:url glob:url-pattern #optional
	// }
	d.Next() // Consume directive name ("paw_auth")
	if d.NextArg() {
		return d.ArgErr() // No arguments expected
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "client_id":
			if !d.NextArg() {
				return d.ArgErr()
			}
			p.ClientID = d.Val()
		case "client_secret":
			if !d.NextArg() {
				return d.ArgErr()
			}
			p.ClientSecret = d.Val()
		case "roles":
			p.Roles = d.RemainingArgs()
			if len(p.Roles) == 0 {
				return d.ArgErr()
			}
		case "callback_url":
			if !d.NextArg() {
				return d.ArgErr()
			}
			p.CallbackURL = d.Val()
		case "public_urls":
			p.PublicURLs = d.RemainingArgs()
			if len(p.PublicURLs) == 0 {
				return d.ArgErr()
			}
		default:
			return d.Errf("unrecognized subdirective '%s'", d.Val())
		}
	}

	return nil
}

var (
	// Interface guards
	_ caddy.Provisioner           = (*Auth)(nil)
	_ caddy.Validator             = (*Auth)(nil)
	_ caddyhttp.MiddlewareHandler = (*Auth)(nil)
	_ caddyfile.Unmarshaler       = (*Auth)(nil)
)
