package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClient_VerifyRedirectURI(t *testing.T) {
	tests := []struct {
		name       string
		registered string
		uri        string
		accepted   bool
	}{
		{
			name:       "exact match",
			registered: "https://app.example.com/callback",
			uri:        "https://app.example.com/callback",
			accepted:   true,
		},
		{
			name:       "path prefix match",
			registered: "https://app.example.com/callback",
			uri:        "https://app.example.com/callback/nested",
			accepted:   true,
		},
		{
			name:       "host without port matches any port",
			registered: "http://localhost",
			uri:        "http://localhost:18080/paw/callback",
			accepted:   true,
		},
		{
			name:       "registered port must match",
			registered: "http://localhost:8080/callback",
			uri:        "http://localhost:9090/callback",
			accepted:   false,
		},
		{
			name:       "host case is ignored",
			registered: "https://app.example.com",
			uri:        "https://APP.EXAMPLE.COM/",
			accepted:   true,
		},
		{
			name:       "scheme must match",
			registered: "https://app.example.com",
			uri:        "http://app.example.com/",
			accepted:   false,
		},
		{
			name:       "other host",
			registered: "https://app.example.com",
			uri:        "https://evil.example.com/",
			accepted:   false,
		},
		{
			name:       "registered host in the userinfo part",
			registered: "https://app.example.com",
			uri:        "https://app.example.com@evil.example.com/",
			accepted:   false,
		},
		{
			name:       "registered host as path prefix",
			registered: "https://app.example.com",
			uri:        "https://evil.example.com/app.example.com",
			accepted:   false,
		},
		{
			name:       "registered host as host suffix",
			registered: "https://app.example.com",
			uri:        "https://app.example.com.evil.com/",
			accepted:   false,
		},
		{
			name:       "other path",
			registered: "https://app.example.com/callback",
			uri:        "https://app.example.com/other",
			accepted:   false,
		},
		{
			name:       "no registered redirect URI",
			registered: "",
			uri:        "https://evil.example.com/",
			accepted:   false,
		},
		{
			name:       "non http scheme",
			registered: "https://app.example.com",
			uri:        "javascript:alert(1)",
			accepted:   false,
		},
		{
			name:       "relative URI",
			registered: "https://app.example.com",
			uri:        "/callback",
			accepted:   false,
		},
		{
			name:       "second registration matches",
			registered: "https://a.example.com,https://b.example.com",
			uri:        "https://b.example.com/x",
			accepted:   true,
		},
		{
			name:       "empty registration is ignored",
			registered: "https://app.example.com,",
			uri:        "https://evil.example.com/",
			accepted:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{RedirectURIPrefixs: tt.registered}
			assert.Equal(t, tt.accepted, client.VerifyRedirectURI(tt.uri))
		})
	}
}
