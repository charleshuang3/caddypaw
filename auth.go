package caddypaw

import (
	"errors"
	"fmt"
	"net/http"

	"bitbucket.org/creachadair/stringset"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/dgraph-io/ristretto/v2"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/oauth2"

	"github.com/charleshuang3/caddypaw/internal/config"
)

var (
	httpClient = http.DefaultClient
)

func init() {
	caddy.RegisterModule(AuthModule{})
	httpcaddyfile.RegisterHandlerDirective("paw_auth", parseDirectivePawAuth)
}

func parseDirectivePawAuth(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	a := &AuthModule{}
	err := a.UnmarshalCaddyfile(h.Dispenser)
	return a, err
}

type authType uint8

const (
	authTypeNone authType = iota
	authTypeBasicAuth
	authTypeServerCookies
)

func (ty *authType) String() string {
	switch *ty {
	case authTypeBasicAuth:
		return "basic_auth"
	case authTypeServerCookies:
		return "server_cookies"
	default:
		return "none"
	}
}

// AuthModule is a middleware module that handles authentication and authorization.
type AuthModule struct {
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

	oauth2Config *oauth2.Config

	basicAuthCache *ristretto.Cache[string, *basicAuth]
	stateCache     *ristretto.Cache[string, string]
}

// CaddyModule returns the Caddy module information.
func (AuthModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.paw_auth",
		New: func() caddy.Module { return new(AuthModule) },
	}
}

// Provision sets up the module.
func (a *AuthModule) Provision(ctx caddy.Context) error {
	var err error
	a.basicAuthCache, err = ristretto.NewCache(&ristretto.Config[string, *basicAuth]{
		NumCounters: 1e7,
		MaxCost:     1e7,
		BufferItems: 16,
	})
	if err != nil {
		return err
	}

	a.stateCache, err = ristretto.NewCache(&ristretto.Config[string, string]{
		NumCounters: 1e7,
		MaxCost:     1e7,
		BufferItems: 16,
	})
	if err != nil {
		return err
	}

	a.logger = ctx.Logger(a).With(zap.String("client_id", a.ClientID))

	appModule, err := ctx.App(globalOptionAppName)
	if err != nil {
		return err
	}

	gOption := appModule.(*globalOptionModule)

	a.authnConfig = gOption.AuthnConfig
	a.publicKey = gOption.publicKey

	a.oauth2Config = &oauth2.Config{
		ClientID:     a.ClientID,
		ClientSecret: a.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: a.authnConfig.TokenURL,
			AuthURL:  a.authnConfig.AuthURL,
		},
		RedirectURL: a.CallbackURL,
		Scopes:      []string{"openid", "profile", "email", "offline_access"},
	}

	return nil
}

// Validate ensures the module's configuration is valid.
func (a *AuthModule) Validate() error {
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
func (a *AuthModule) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	status, user, err := a.checkAuth(w, r)

	switch status {
	case http.StatusOK:
		// Have userinfo, can go to next checker
		if ok := user.checkRole(a.Roles); !ok {
			return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("forbidden"))
		}
		return next.ServeHTTP(w, r)
	case http.StatusFound:
		// 302 redirect. checkAuth() already wrote status and location to body.
		// The caller (ServeHTTP) just needs to know not to call the next handler.
		return nil
	case http.StatusBadRequest:
		if c := a.logger.Check(zapcore.ErrorLevel, "bad request error"); c != nil {
			c.Write(zap.Error(err), zap.String("url", r.RequestURI))
		}
		if err != nil && errors.Is(err, caddyhttp.HandlerError{}) {
			return err
		}
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("bad request"))
	case http.StatusUnauthorized:
		// Have 401 error
		if c := a.logger.Check(zapcore.ErrorLevel, "unauthorized error"); c != nil {
			c.Write(zap.Error(err), zap.String("url", r.RequestURI))
		}
		return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("not authenticated"))
	case http.StatusInternalServerError:
		// Have error, return 500 error to client
		if c := a.logger.Check(zapcore.ErrorLevel, "internal error"); c != nil {
			c.Write(zap.Error(err), zap.String("url", r.RequestURI))
		}
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("internal error"))
	default:
		// Fallback for unexpected status codes
		if c := a.logger.Check(zapcore.ErrorLevel, "checkAuth() returned unexpected status"); c != nil {
			c.Write(zap.Int("status", status), zap.Error(err), zap.String("url", r.RequestURI))
		}
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("unexpected authentication status"))
	}
}

type userInfo struct {
	Username   string `json:"username"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	Roles      string `json:"roles"` // multi-roles splitted by " "
	Picture    string `json:"picture"`
	Expiration int64  `json:"exp"`

	roles stringset.Set
}

func (u *userInfo) checkRole(allowRoles []string) bool {
	for _, r := range allowRoles {
		if u.roles.Contains(r) {
			return true
		}
	}
	return false
}

// checkAuth of request, return http status code, user info and error.
// If status is http.StatusFound (302), the response is already written by this function or its sub-functions.
func (a *AuthModule) checkAuth(w http.ResponseWriter, r *http.Request) (int, *userInfo, error) {
	switch a.AuthType {
	case authTypeBasicAuth:
		return a.checkBasicAuth(w, r)
	case authTypeServerCookies:
		return a.checkServerCookies(w, r)
	default:
		return http.StatusInternalServerError, nil, fmt.Errorf("unknown auth type: %d", a.AuthType)
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (a *AuthModule) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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
	_ caddy.Provisioner           = (*AuthModule)(nil)
	_ caddy.Validator             = (*AuthModule)(nil)
	_ caddyhttp.MiddlewareHandler = (*AuthModule)(nil)
	_ caddyfile.Unmarshaler       = (*AuthModule)(nil)
)
