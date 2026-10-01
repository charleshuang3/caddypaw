package oidc

import (
	_ "embed"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"uuid"

	"github.com/charleshuang3/caddypaw/pkg/authn/storage"
)

var (
	stateRE = regexp.MustCompile(`^[a-zA-Z0-9-_.]+$`)
)

type handleAuthorizeParams struct {
	ClientID     string `form:"client_id" binding:"required"`
	RedirectURI  string `form:"redirect_uri" binding:"required"`
	ResponseType string `form:"response_type"`
	State        string `form:"state"`
	Scope        string `form:"scope"`
	// Nonce is optional (OIDC Core §3.1.2.1); echoed into the id_token when set.
	Nonce string `form:"nonce"`
}

// responseAuthorizeError redirects back to the client's redirect_uri with the
// standard OAuth2 error parameters (RFC 6749 §4.1.2.1). Only call this after
// the redirect_uri has been validated, otherwise it is an open redirect.
func responseAuthorizeError(c *gin.Context, redirectURI, errCode, description, state string) {
	logMayHack(c, description)

	u, err := url.Parse(redirectURI)
	if err != nil {
		// redirect_uri was already verified against the client's registered
		// prefixes, so this should never happen.
		c.String(http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
		return
	}

	q := u.Query()
	q.Set("error", errCode)
	q.Set("error_description", description)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()

	c.Redirect(http.StatusFound, u.String())
}

// handleAuthorize handles the authorization request for the authorization code flow.
func (o *OpenIDProvider) handleAuthorize(c *gin.Context) {
	params := &handleAuthorizeParams{}

	if err := c.ShouldBindQuery(params); err != nil {
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Missing required parameters")
		return
	}

	// Fetch client from database using clientID. Until the redirect_uri is
	// verified against the registered URIs, errors must NOT redirect to it.
	client, err := storage.GetClientByID(o.db, params.ClientID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Client not found")
			return
		} else {
			logger.Error().Err(err).Msg("Failed to get client")
			c.String(http.StatusInternalServerError, "Database error")
			return
		}
	}

	if !client.VerifyRedirectURI(params.RedirectURI) {
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Invalid redirect URI")
		return
	}

	// From here on the redirect_uri is trusted; report errors by redirecting
	// back to it with standard OAuth2 error parameters.

	if params.ResponseType != "code" {
		desc := "Unsupported response type, only 'code' is supported"
		if params.ResponseType == "" {
			desc = "Missing response_type"
		}
		responseAuthorizeError(c, params.RedirectURI, "invalid_request", desc, params.State)
		return
	}

	if params.State != "" && !stateRE.MatchString(params.State) {
		responseAuthorizeError(c, params.RedirectURI, "invalid_request", "Invalid state parameter format", params.State)
		return
	}

	// An omitted scope defaults to all scopes the client is allowed to request.
	if params.Scope == "" {
		params.Scope = client.AllowedScopes
	}

	scopes := strings.Split(params.Scope, " ")
	if !client.VerifyScopesAllowed(scopes) {
		responseAuthorizeError(c, params.RedirectURI, "invalid_scope", "Invalid scope", params.State)
		return
	}

	// The state doubles as the AuthState storage key. When the client omits
	// it, generate one so concurrent requests never collide; the client simply
	// ignores the echoed value.
	if params.State == "" {
		params.State = uuid.New().String()
	} else if _, ok := o.authStateStorage.Get(params.State); ok {
		responseAuthorizeError(c, params.RedirectURI, "invalid_request", "Conflict state", params.State)
		return
	}

	o.authStateStorage.Set(params.State, &storage.AuthState{
		ClientID:    params.ClientID,
		RedirectURI: params.RedirectURI,
		Scopes:      scopes,
		Nonce:       params.Nonce,
	})

	googleLoginURL := o.config.SSO.Google.oauth2Config().AuthCodeURL(params.State)

	// for google login only, we can skip the login page and redirect to google login.
	if client.AllowGoogleLogin && !client.AllowPasswordLogin {
		c.Redirect(http.StatusFound, googleLoginURL)
		return
	}

	// Return the login page with the state value.
	if err := o.RenderLoginPage(c.Writer, &LoginPageData{
		Title:              o.config.Title,
		AllowPasswordLogin: client.AllowPasswordLogin,
		AllowGoogleLogin:   client.AllowGoogleLogin,
		State:              params.State,
		GoogleLoginURL:     googleLoginURL,
	}); err != nil {
		logger.Error().Err(err).Msg("Failed to render login page")
		c.String(http.StatusInternalServerError, "Failed to render login page")
	}
}

//go:embed templates/login_page.html
var loginPageTemplateFile string

// loginPageTemplate is the HTML template for the login page.
var loginPageTemplate = template.Must(template.New("loginPage").Parse(loginPageTemplateFile))

// LoginPageData holds the data to be passed to the login page template.
type LoginPageData struct {
	Title              string
	AllowPasswordLogin bool
	AllowGoogleLogin   bool
	State              string
	GoogleLoginURL     string
}

// RenderLoginPage renders the login page with the provided state value.
func (o *OpenIDProvider) RenderLoginPage(w http.ResponseWriter, data *LoginPageData) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	return loginPageTemplate.Execute(w, data)
}
