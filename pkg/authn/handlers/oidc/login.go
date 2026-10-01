package oidc

import (
	_ "embed"
	"errors"
	"html/template"
	"net/http"
	"uuid"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/charleshuang3/caddypaw/pkg/authn/models"
	"github.com/charleshuang3/caddypaw/pkg/authn/storage"
)

type handleLoginParams struct {
	Username string `form:"username" binding:"required"`
	Password string `form:"password" binding:"required"`
	State    string `form:"state" binding:"required"`
}

// handleLogin handles user choosing to login with username and password.
func (o *OpenIDProvider) handleLogin(c *gin.Context) {
	params := &handleLoginParams{}

	// 1. Use gin binding; if missing params, response 400 bad request
	if err := c.ShouldBind(params); err != nil {
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Missing required parameters")
		return
	}

	// 2. Check state in storage
	authState, ok := o.authStateStorage.Get(params.State)
	if !ok {
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Invalid state")
		return
	}
	// Remove state after use to prevent replay attacks
	o.authStateStorage.Delete(params.State)

	// 3. Check user in db (username or email)
	user, err := storage.GetUserByUsernameOrEmail(o.db, params.Username)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logMayHack(c, "User not found")
			o.render401(c, "Invalid username or password")
			return
		}
		logger.Error().Err(err).Msg("Database error during login")
		c.String(http.StatusInternalServerError, "Database error")
		return
	}

	// 4. Check password use user.CheckPassword()
	if !user.CheckPassword(params.Password) {
		logMayHack(c, "Invalid password")
		o.render401(c, "Invalid username or password")
		return
	}

	// Successful login logic:
	o.successfulLogin(params.State, authState, user, c)
}

func (o *OpenIDProvider) successfulLogin(state string, authState *storage.AuthState, user *models.User, c *gin.Context) {
	// 1. Generate an authorization code using UUID
	authCode := uuid.New().String()

	// 2. Store the authorization code with relevant details
	o.authCodeStorage.Set(authCode, &storage.AuthCode{
		UserID:      user.ID,
		ClientID:    authState.ClientID,
		Scopes:      authState.Scopes,
		RedirectURI: authState.RedirectURI,
	})

	// 3. Redirect the user to authState.RedirectURI with the authorization code and state
	// client on RedirectURI can use the state to redirect to other URL
	redirectURL := authState.RedirectURI + "?code=" + authCode + "&state=" + state
	c.Redirect(http.StatusFound, redirectURL)
}

var (
	//go:embed templates/401.html
	err401TemplateFile string

	err401Template = template.Must(template.New("401").Parse(err401TemplateFile))
)

type ErrorPageData struct {
	ErrorMessage string
}

func (o *OpenIDProvider) render401(c *gin.Context, errorMessage string) {
	data := ErrorPageData{ErrorMessage: errorMessage}
	c.Status(http.StatusUnauthorized)
	err := err401Template.Execute(c.Writer, data)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to render 401 template")
		c.String(http.StatusInternalServerError, "Internal Server Error")
	}
}
