package oidc

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func useActualLoginPageTemplate(t *testing.T) {
	t.Helper()
	// No need to override, using the actual template defined in loginpage.go
}

func TestRenderLoginPage(t *testing.T) {
	useActualLoginPageTemplate(t)

	// Create a test provider with some configuration
	provider := &OpenIDProvider{
		config: &OIDCProviderConfig{
			Title: "Test Login",
		},
	}

	// Test cases
	tests := []struct {
		name               string
		state              string
		allowPasswordLogin bool
		allowGoogleLogin   bool
		wantTitle          string
		wantState          string
		wantPasswordForm   bool
		wantGoogleButton   bool
		wantOrDivider      bool
		wantRememberChoice bool
	}{
		{
			name:               "valid state with both login options",
			state:              "test-state-123",
			allowPasswordLogin: true,
			allowGoogleLogin:   true,
			wantTitle:          "Test Login",
			wantState:          "test-state-123",
			wantPasswordForm:   true,
			wantGoogleButton:   true,
			wantOrDivider:      true,
			wantRememberChoice: true,
		},
		{
			name:               "valid state with only password login",
			state:              "test-state-123",
			allowPasswordLogin: true,
			allowGoogleLogin:   false,
			wantTitle:          "Test Login",
			wantState:          "test-state-123",
			wantPasswordForm:   true,
			wantGoogleButton:   false,
			wantOrDivider:      false,
		},
		{
			name:               "valid state with only Google login",
			state:              "test-state-123",
			allowPasswordLogin: false,
			allowGoogleLogin:   true,
			wantTitle:          "Test Login",
			wantState:          "test-state-123",
			wantPasswordForm:   false,
			wantGoogleButton:   true,
			wantOrDivider:      false,
		},
		{
			name:               "empty state with no login options",
			state:              "",
			allowPasswordLogin: false,
			allowGoogleLogin:   false,
			wantTitle:          "Test Login",
			wantState:          "",
			wantPasswordForm:   false,
			wantGoogleButton:   false,
			wantOrDivider:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use httptest.ResponseRecorder to capture the output
			w := httptest.NewRecorder()
			err := provider.RenderLoginPage(w, &LoginPageData{
				Title:              provider.config.Title,
				State:              tt.state,
				AllowPasswordLogin: tt.allowPasswordLogin,
				AllowGoogleLogin:   tt.allowGoogleLogin,
			})

			require.NoError(t, err, "RenderLoginPage() should not return an error")

			// Check the response headers for Content-Type
			contentType := w.Header().Get("Content-Type")
			assert.Equal(t, "text/html; charset=utf-8", contentType, "Response Content-Type should be HTML")

			// Check the rendered output
			body := w.Body.String()
			expectedTitle := "<h2>" + tt.wantTitle + "</h2>"
			assert.Contains(t, body, expectedTitle, "RenderLoginPage() output should contain title")

			// Check for password form
			if tt.wantPasswordForm {
				assert.Contains(t, body, "id=\"loginForm\"", "RenderLoginPage() output should contain password form when allowed")
				assert.Contains(t, body, "name=\"state\" value=\""+tt.wantState+"\"", "RenderLoginPage() output should contain state in form")
			} else {
				assert.NotContains(t, body, "id=\"loginForm\"", "RenderLoginPage() output should not contain password form when not allowed")
			}

			// Check for Google login button
			if tt.wantGoogleButton {
				assert.Contains(t, body, "class=\"google-login-button\"", "RenderLoginPage() output should contain Google login button when allowed")
			} else {
				assert.NotContains(t, body, "class=\"google-login-button\"", "RenderLoginPage() output should not contain Google login button when not allowed")
			}

			// Check for OR divider
			if tt.wantOrDivider {
				assert.Contains(t, body, "class=\"or-divider\"", "RenderLoginPage() output should contain OR divider when both login options are allowed")
			} else {
				assert.NotContains(t, body, "class=\"or-divider\"", "RenderLoginPage() output should not contain OR divider when not both login options are allowed")
			}

			// Remember-my-choice is only offered when there is a choice to remember.
			if tt.wantRememberChoice {
				assert.Contains(t, body, "id=\"rememberChoice\"", "RenderLoginPage() output should contain remember-choice checkbox when both login options are allowed")
			} else {
				assert.NotContains(t, body, "id=\"rememberChoice\"", "RenderLoginPage() output should not contain remember-choice checkbox when not both login options are allowed")
			}
		})
	}
}

func TestLoginPageDataMultipleLoginMethods(t *testing.T) {
	tests := []struct {
		name     string
		data     LoginPageData
		wantN    int
		wantMult bool
	}{
		{"none", LoginPageData{}, 0, false},
		{"password only", LoginPageData{AllowPasswordLogin: true}, 1, false},
		{"google only", LoginPageData{AllowGoogleLogin: true}, 1, false},
		{"password and google", LoginPageData{AllowPasswordLogin: true, AllowGoogleLogin: true}, 2, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantN, tt.data.LoginMethodCount())
			assert.Equal(t, tt.wantMult, tt.data.MultipleLoginMethods())
		})
	}
}
