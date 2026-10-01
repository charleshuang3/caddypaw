package oidc

import (
	_ "embed"
	"errors"
	"html/template"
	"net/http"
	"regexp"
	"strings"

	"github.com/badoux/checkmail"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/charleshuang3/caddypaw/pkg/authn/models"
	"github.com/charleshuang3/caddypaw/pkg/authn/storage"
)

//go:embed templates/register_page.html
var registerPageTemplateFile string

var registerPageTemplate = template.Must(template.New("registerPage").Parse(registerPageTemplateFile))

// RegisterPageData holds the data to be passed to the register page template.
type RegisterPageData struct {
	Title       string
	State       string
	ClientID    string
	RedirectURI string
	Scope       string
}

func (o *OpenIDProvider) registerPage(c *gin.Context) {
	state := c.Query("state")
	if state == "" {
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Missing state parameter")
		return
	}

	authState, ok := o.authStateStorage.Get(state)
	if !ok {
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Invalid or expired state")
		return
	}

	data := &RegisterPageData{
		Title:       o.config.Title + " - Register",
		State:       state,
		ClientID:    authState.ClientID,
		RedirectURI: authState.RedirectURI,
		Scope:       strings.Join(authState.Scopes, " "),
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	if err := registerPageTemplate.Execute(c.Writer, data); err != nil {
		logger.Error().Err(err).Msg("Failed to render register page")
		c.String(http.StatusInternalServerError, "Failed to render register page")
	}
}

type handleUserRegisterParams struct {
	Username       string `form:"username" binding:"required"`
	Email          string `form:"email" binding:"required"`
	Password       string `form:"password" binding:"required"`
	InvitationCode string `form:"invitation_code" binding:"required"`
	State          string `form:"state" binding:"required"`
}

var (
	usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9-_]{4,12}$`)
)

const (
	allowedSpecialChars = `!@#$%^&*()_+\-=[]{};':"\|,.<>/?`
	allAllowedChars     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" + allowedSpecialChars
)

func validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	hasNumber := false
	hasLower := false
	hasUpper := false
	hasSpecial := false

	for _, char := range password {
		if char >= '0' && char <= '9' {
			hasNumber = true
		} else if char >= 'a' && char <= 'z' {
			hasLower = true
		} else if char >= 'A' && char <= 'Z' {
			hasUpper = true
		} else if strings.ContainsRune(allowedSpecialChars, char) {
			hasSpecial = true
		} else {
			// Character is not in any of the allowed groups
			return errors.New("password contains disallowed characters")
		}
	}

	if !hasNumber {
		return errors.New("password must contain at least one number")
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	return nil
}

func (o *OpenIDProvider) handleUserRegister(c *gin.Context) {
	params := &handleUserRegisterParams{}

	if err := c.ShouldBind(params); err != nil {
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Missing required parameters: "+err.Error())
		return
	}

	// Validate Username
	if !usernameRegex.MatchString(params.Username) {
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Invalid username format. Must be 4-12 characters and contain only letters, numbers, hyphens, and underscores.")
		return
	}

	// Validate Email
	if err := checkmail.ValidateFormat(params.Email); err != nil {
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Invalid email format.")
		return
	}

	// Validate Password
	if err := validatePassword(params.Password); err != nil {
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, err.Error())
		return
	}

	// Validate Invitation Code (not empty)
	if strings.TrimSpace(params.InvitationCode) == "" {
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Invitation code cannot be empty.")
		return
	}

	// Check state in storage
	authState, ok := o.authStateStorage.Get(params.State)
	if !ok {
		responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Invalid or expired state.")
		return
	}
	o.authStateStorage.Delete(params.State) // Remove state after use

	// Check invitation code
	invitation, err := storage.GetInvitationByCode(o.db, params.InvitationCode)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			responseErrorAndLogMaybeHack(c, http.StatusBadRequest, "Invalid invitation code.")
			return
		}
		logger.Error().Err(err).Str("invitation_code", params.InvitationCode).Msg("Failed to get invitation code")
		c.String(http.StatusInternalServerError, "Error validating invitation code.")
		return
	}

	// Check if user already exists (username or email)
	_, err = storage.GetUserByUsernameOrEmail(o.db, params.Username)
	if err == nil { // User found with this username
		c.String(http.StatusConflict, "Username already exists.")
		return
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) { // Some other DB error
		logger.Error().Err(err).Str("username", params.Username).Msg("Error checking username existence")
		c.String(http.StatusInternalServerError, "Database error.")
		return
	}

	_, err = storage.GetUserByUsernameOrEmail(o.db, params.Email)
	if err == nil { // User found with this email
		c.String(http.StatusConflict, "Email already registered.")
		return
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) { // Some other DB error
		logger.Error().Err(err).Str("email", params.Email).Msg("Error checking email existence")
		c.String(http.StatusInternalServerError, "Database error.")
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(params.Password), bcrypt.DefaultCost)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to hash password")
		c.String(http.StatusInternalServerError, "Error processing registration.")
		return
	}

	// Create user
	newUser := &models.User{
		Username:       params.Username,
		Email:          params.Email,
		HashedPassword: string(hashedPassword),
		Roles:          invitation.Roles, // Assign roles from invitation
	}

	if err := storage.CreateUser(o.db, newUser); err != nil {
		logger.Error().Err(err).Msg("Failed to create user")
		c.String(http.StatusInternalServerError, "Failed to create user.")
		return
	}

	// Update invitation use count
	invitation.UseCount++
	if err := storage.UpdateInvitation(o.db, invitation); err != nil {
		logger.Error().Err(err).Str("invitation_code", invitation.Code).Msg("Failed to update invitation use count")
		// Continue even if this fails, user is already created. Log error.
	}

	// Successful registration, proceed to login
	o.successfulLogin(params.State, authState, newUser, c)
}
