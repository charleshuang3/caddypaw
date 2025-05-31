package caddypaw

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"go.uber.org/zap"

	"github.com/charleshuang3/caddypaw/internal/config"
)

func init() {
	caddy.RegisterModule(Auth{})
	httpcaddyfile.RegisterHandlerDirective("paw_auth", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	return &Auth{}, nil
}

type authType uint8

const (
	authTypeNone authType = iota
	authTypeBasicAuth
	authTypeServerCookies
)

// Auth is a middleware module that handles authentication and authorization.
type Auth struct {
	logger *zap.Logger

	// from paw_auth directive

	AuthType     authType      `json:"auth_type,omitempty"`
	ClientID     string        `json:"client_id,omitempty"`
	ClientSecret string        `json:"client_secret,omitempty"`
	Roles        []string      `json:"roles,omitempty"`
	CallbackURL  string        `json:"callback_url,omitempty"`
	PublicURLs   []*urlMatcher `json:"public_urls,omitempty"`

	// from paw_global_option
	authnConfig *config.AuthnConfig
	publicKey   jwk.Key
}

// CaddyModule returns the Caddy module information.
func (Auth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.paw_auth",
		New: func() caddy.Module { return new(Auth) },
	}
}

// Provision sets up the module.
func (a *Auth) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger(a)

	appModule, err := ctx.App(globalOptionAppName)
	if err != nil {
		return err
	}

	gOption := appModule.(*globalOptionModule)

	a.authnConfig = gOption.AuthnConfig
	a.publicKey = gOption.publicKey

	return nil
}

// Validate ensures the module's configuration is valid.
func (a *Auth) Validate() error {
	if a.AuthType == authTypeNone {
		return fmt.Errorf("auth_type is required, allow value basic_auth or server_cookies")
	}
	if a.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	if a.ClientSecret == "" {
		return fmt.Errorf("client_secret is required")
	}
	if len(a.Roles) == 0 {
		return fmt.Errorf("roles are required")
	}
	return nil
}

// ServeHTTP implements the caddyhttp.MiddlewareHandler interface.
func (a *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
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
func (a *Auth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// the caddyfile config:
	// paw_auth {
	//   basic_auth / server_cookies
	//   client_id the-client-id
	//   client_secret the-client-secret
	//   roles role1 role2
	//   callback_url callback-url # optional
	//   public_urls path_prefix:/path path_prefix:/path #optional
	// }
	d.Next() // Consume directive name ("paw_auth")
	if d.NextArg() {
		return d.ArgErr() // No arguments expected
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "basic_auth":
			if a.AuthType != authTypeNone {
				return d.SyntaxErr("auth type can only be set once")
			}
			a.AuthType = authTypeBasicAuth
		case "server_cookies":
			if a.AuthType != authTypeNone {
				return d.SyntaxErr("auth type can only be set once")
			}
			a.AuthType = authTypeServerCookies
		case "client_id":
			if !d.NextArg() {
				return d.ArgErr()
			}
			a.ClientID = d.Val()
		case "client_secret":
			if !d.NextArg() {
				return d.ArgErr()
			}
			a.ClientSecret = d.Val()
		case "roles":
			a.Roles = d.RemainingArgs()
			if len(a.Roles) == 0 {
				return d.ArgErr()
			}
		case "callback_url":
			if !d.NextArg() {
				return d.ArgErr()
			}
			a.CallbackURL = d.Val()
		case "public_urls":
			list := d.RemainingArgs()

			if len(list) == 0 {
				return d.SyntaxErr("no public_urls specified")
			}

			for _, it := range list {
				u, err := urlMatcherFromStr(it)
				if err != nil {
					return d.SyntaxErr(err.Error())
				}
				a.PublicURLs = append(a.PublicURLs, u)
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
