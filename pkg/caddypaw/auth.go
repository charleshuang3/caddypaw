package caddypaw

import (
	"errors"
	"fmt"
	"net/http"

	"strings"

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

	"github.com/charleshuang3/caddypaw/pkg/caddypaw/config"
	"github.com/charleshuang3/caddypaw/pkg/waf"
)

var (
	httpClient = http.DefaultClient
)

func init() {
	caddy.RegisterModule(authModule{})
	httpcaddyfile.RegisterHandlerDirective("paw_auth", parseDirectivePawAuth)
}

func parseDirectivePawAuth(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	a := &authModule{}
	err := a.UnmarshalCaddyfile(h.Dispenser)
	return a, err
}

type authType uint8

const (
	authTypeNone authType = iota
	authTypeBasicAuth
	authTypeServerCookies
	authTypeBearerToken
)

func (ty *authType) String() string {
	switch *ty {
	case authTypeBasicAuth:
		return "basic_auth"
	case authTypeServerCookies:
		return "server_cookies"
	case authTypeBearerToken:
		return "bearer_token"
	default:
		return "none"
	}
}

// authModule is a middleware module that handles authentication and authorization.
type authModule struct {
	logger *zap.Logger

	// from paw_auth directive

	AuthType     authType      `json:"auth_type,omitempty"`
	ClientID     string        `json:"client_id,omitempty"`
	ClientSecret string        `json:"client_secret,omitempty"`
	Roles        []string      `json:"roles,omitempty"`
	CallbackURL  string        `json:"callback_url,omitempty"`
	PublicURLs   []*urlMatcher `json:"public_urls,omitempty"`
	Token        string        `json:"token,omitempty"`
	WAFConfig    *waf.Config   `json:"waf,omitempty"`

	// from paw_global_option
	authnConfig *config.AuthnConfig
	publicKey   jwk.Key

	oauth2Config *oauth2.Config

	basicAuthCache *ristretto.Cache[string, *basicAuth]
	stateCache     *ristretto.Cache[string, string]

	waf *waf.WAF
	// wafDetectOnly is a second engine forced to DetectionOnly, built only for
	// AfterAuthDetectOnly. The blocking engine still guards public URLs, while
	// authenticated requests and unauthenticated probes must be fully inspected
	// (body included) without ever being interrupted. phase1_only and skip need no
	// second engine: they observe through the blocking one, phase 1 only.
	wafDetectOnly *waf.WAF
	reporter      *waf.Reporter
}

// CaddyModule returns the Caddy module information.
func (authModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.paw_auth",
		New: func() caddy.Module { return new(authModule) },
	}
}

// Provision sets up the module.
func (a *authModule) Provision(ctx caddy.Context) error {
	if err := a.configValidate(); err != nil {
		return err
	}

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

	var firewallURL string
	if a.authnConfig != nil {
		firewallURL = a.authnConfig.FirewallURL
	}
	a.reporter = waf.NewReporter(a.logger, firewallURL)

	if a.WAFConfig != nil {
		a.waf, err = waf.NewWAF(a.WAFConfig, a.logger)
		if err != nil {
			return fmt.Errorf("initializing waf: %w", err)
		}
		if a.WAFConfig.AfterAuthMode() == waf.AfterAuthDetectOnly {
			// Both the authenticated and the failed-auth path need an engine that can
			// never interrupt the request in this mode.
			a.wafDetectOnly, err = waf.NewWAFDetectOnly(a.WAFConfig, a.logger)
			if err != nil {
				return fmt.Errorf("initializing detect-only waf: %w", err)
			}
		}
	}

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

// configValidate ensures the module's configuration is valid.
func (a *authModule) configValidate() error {
	if a.AuthType == authTypeNone {
		return fmt.Errorf("auth_type is required, allow value basic_auth or server_cookies")
	}
	if a.AuthType == authTypeBearerToken {
		if a.Token == "" {
			return fmt.Errorf("token is required")
		}
		return nil
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
	if a.AuthType != authTypeBasicAuth && a.CallbackURL == "" {
		return fmt.Errorf("callback_url is required")
	}

	return nil
}

// ServeHTTP implements the caddyhttp.MiddlewareHandler interface.
func (a *authModule) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// All firewall factors of this request are collected here and flushed once on
	// return, so no branch can report the same request twice.
	v := &violations{}
	defer a.report(r, v)

	isPublic := a.isPublicURL(r.URL.Path)

	// The WAF runs before authentication unless a post-auth mode is configured:
	// knowing whether a request is authenticated requires checkAuth() to run
	// first. Public URLs are always evaluated in blocking mode, whether or not a
	// post-auth mode is set, because they are reachable without credentials and
	// must not become a WAF-free entry point.
	if a.waf != nil && (a.wafAfterAuth() == waf.AfterAuthBlock || isPublic) {
		if err := a.blockOnWAFViolation(r, a.waf, v); err != nil {
			return err
		}
	}

	if isPublic {
		return next.ServeHTTP(w, r)
	}

	status, user, err := a.checkAuth(w, r, v)

	if status != http.StatusOK {
		// Failed authentication is the most suspicious traffic there is. Inspect
		// it without blocking (the blocking engine has not run in after_auth
		// modes), so that unauthenticated probes still reach the ban pipeline.
		a.inspectFailedRequest(r, v)
	}

	switch status {
	case http.StatusOK:
		// bearer token does not use role
		if a.AuthType != authTypeBearerToken {
			// Have userinfo, can go to next checker
			if ok := user.checkRole(a.Roles); !ok {
				return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("forbidden"))
			}
		}
		if err := a.inspectAuthenticatedRequest(r, v); err != nil {
			return err
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
	case http.StatusBadGateway:
		// authn server unavailable (5xx / network error); fail instead of
		// redirecting, which would risk a redirect loop.
		if c := a.logger.Check(zapcore.ErrorLevel, "authn server error"); c != nil {
			c.Write(zap.Error(err), zap.String("url", r.RequestURI))
		}
		return caddyhttp.Error(http.StatusBadGateway, fmt.Errorf("authn server error"))
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

// isPublicURL reports whether path matches one of the configured public_urls.
func (a *authModule) isPublicURL(path string) bool {
	for _, u := range a.PublicURLs {
		if u.Match(path) {
			return true
		}
	}
	return false
}

// wafAfterAuth returns the configured post-authentication WAF mode. The
// standalone paw_waf directive and configurations without a waf block always
// behave as AfterAuthBlock.
func (a *authModule) wafAfterAuth() string {
	return a.WAFConfig.AfterAuthMode()
}

// blockOnWAFViolation evaluates r with engine and blocks it when a rule
// interrupts. Evaluation errors fail open. A violation is recorded on v and
// reported by ServeHTTP, so the request is counted exactly once.
func (a *authModule) blockOnWAFViolation(r *http.Request, engine *waf.WAF, v *violations) error {
	result, err := engine.ProcessRequest(r)
	if err != nil {
		a.logger.Error("waf evaluation error; failing open", zap.Error(err))
		return nil
	}
	if !result.Blocked {
		return nil
	}

	v.recordMatch(result.RuleID, waf.WeightBlocked)
	return blockError(result)
}

// blockError converts a blocking WAF result into the handler error to return.
func blockError(result waf.Result) error {
	status := result.Status
	if status == 0 {
		status = http.StatusForbidden
	}
	return caddyhttp.Error(status, fmt.Errorf("waf rule %d triggered", result.RuleID))
}

// inspectAuthenticatedRequest applies the configured after_auth mode to a
// request that already passed authentication.
func (a *authModule) inspectAuthenticatedRequest(r *http.Request, v *violations) error {
	if a.waf == nil {
		return nil
	}

	switch a.wafAfterAuth() {
	case waf.AfterAuthSkip:
		return nil
	case waf.AfterAuthPhase1Only:
		// Body inspection is what makes WebDAV-style uploads expensive, so only
		// the URI and headers are checked here. Violations still block.
		result, err := a.waf.ProcessRequestPhase1(r)
		if err != nil {
			a.logger.Error("waf evaluation error; failing open", zap.Error(err))
			return nil
		}
		if !result.Blocked {
			return nil
		}
		// The client is authenticated but the request is still refused, so this is a
		// real violation and weighs like any other block.
		v.recordMatch(result.RuleID, waf.WeightBlocked)
		return blockError(result)
	case waf.AfterAuthDetectOnly:
		if a.wafDetectOnly == nil {
			return nil
		}
		result, err := a.wafDetectOnly.ProcessRequest(r)
		if err != nil {
			a.logger.Error("waf evaluation error; failing open", zap.Error(err))
			return nil
		}
		a.collectMatch(r, result, "authenticated request (after_auth detect_only)", v, true)
		return nil
	default:
		return nil
	}
}

// inspectFailedRequest inspects a request that did not authenticate and records
// any WAF match without altering the response.
//
// In after_auth modes the WAF runs after checkAuth, so the 401/302 branches would
// otherwise never reach it. That would silence exactly the most suspicious
// traffic there is: unauthenticated probes that also trip a rule. Recording here
// keeps the /logerr ban pipeline fed. The status code is deliberately left alone,
// because answering 403 instead of 401 would deny the client the basic-auth
// challenge (or login redirect) it needs to retry with credentials.
//
// Only detect_only inspects the body, matching what it does for authenticated
// requests. phase1_only and skip exist to guarantee bodies are never buffered, so
// those deployments judge an unauthenticated request on URI and headers only; the
// interruption is discarded and just the matched rule is reported.
func (a *authModule) inspectFailedRequest(r *http.Request, v *violations) {
	if a.waf == nil {
		return
	}

	var (
		result waf.Result
		err    error
	)
	switch a.wafAfterAuth() {
	case waf.AfterAuthBlock:
		return
	case waf.AfterAuthDetectOnly:
		if a.wafDetectOnly == nil {
			return
		}
		result, err = a.wafDetectOnly.ProcessRequest(r)
	default: // phase1_only, skip
		result, err = a.waf.ProcessRequestPhase1(r)
	}
	if err != nil {
		a.logger.Error("waf evaluation error; failing open", zap.Error(err))
		return
	}
	a.collectMatch(r, result, "unauthenticated request (after_auth)", v, false)
}

// collectMatch records a detect-only match on v and logs the full rule list.
// Nothing is reported here: ServeHTTP flushes v once per request.
//
// observed marks a match on a request that authenticated and was served anyway.
// Those weigh 0: detect_only exists to tune rules and must not have the side
// effect of getting a legitimate client banned. A match on an unauthenticated
// request is a real violation (the request was not served) and weighs as usual.
func (a *authModule) collectMatch(r *http.Request, result waf.Result, context string, v *violations, observed bool) {
	ruleID := result.ReportRuleID()
	if ruleID == 0 {
		return
	}
	a.logger.Warn("waf rule matched on "+context,
		zap.Int("rule_id", ruleID),
		zap.Ints("matched_rule_ids", result.Detected),
		zap.String("url", r.RequestURI),
		zap.Bool("counted", !observed))
	weight := waf.WeightBlocked
	if observed {
		weight = 0
	}
	v.recordMatch(ruleID, weight)
}

func (a *authModule) isAjax(r *http.Request) bool {
	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		return true
	}
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		return true
	}
	// Sec-Fetch-Mode: navigate is for top-level navigation.
	// If it exists and is NOT navigate, it's likely AJAX/Fetch.
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" && mode != "navigate" {
		return true
	}
	return false
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
func (a *authModule) checkAuth(w http.ResponseWriter, r *http.Request, v *violations) (int, *userInfo, error) {
	switch a.AuthType {
	case authTypeBasicAuth:
		return a.checkBasicAuth(w, r, v)
	case authTypeServerCookies:
		return a.checkServerCookies(w, r, v)
	case authTypeBearerToken:
		return a.checkBearerToken(w, r)
	default:
		return http.StatusInternalServerError, nil, fmt.Errorf("unknown auth type: %d", a.AuthType)
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (a *authModule) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// the caddyfile config:
	// paw_auth {
	//   basic_auth / server_cookies
	//   client_id the-client-id
	//   client_secret the-client-secret
	//   roles role1 role2
	//   callback_url callback-url
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
		case "bearer_token":
			if a.AuthType != authTypeNone {
				return d.SyntaxErr("auth type can only be set once")
			}
			a.AuthType = authTypeBearerToken
		case "token":
			if !d.NextArg() {
				return d.ArgErr()
			}
			a.Token = d.Val()
		case "waf":
			if a.WAFConfig != nil {
				return d.SyntaxErr("waf block can only be defined once")
			}
			a.WAFConfig = new(waf.Config)
			if err := a.WAFConfig.UnmarshalCaddyfile(d); err != nil {
				return err
			}

		default:
			return d.Errf("unrecognized subdirective '%s'", d.Val())
		}
	}

	return nil
}

var (
	// Interface guards
	_ caddy.Provisioner           = (*authModule)(nil)
	_ caddyhttp.MiddlewareHandler = (*authModule)(nil)
	_ caddyfile.Unmarshaler       = (*authModule)(nil)
)
