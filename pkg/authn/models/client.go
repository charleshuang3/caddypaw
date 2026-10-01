package models

import (
	"strings"
	"time"

	"github.com/hashicorp/go-set/v3"
)

// Client represents the storage model of an OAuth/OIDC client
// this could also be your database model
type Client struct {
	ClientID           string `gorm:"primarykey"`
	ClientName         string
	CreatedAt          time.Time
	UpdatedAt          time.Time
	Secret             string
	AllowedScopes      string // splitted by " "
	RedirectURIPrefixs string // splitted by ","
	AllowGoogleLogin   bool
	AllowPasswordLogin bool
	AllowHTTPBasicAuth bool
	AccessTokenTTL     int // seconds
	RefreshTokenTTL    int // seconds
}

func (c *Client) AccessTokenTTLDuration() time.Duration {
	return time.Duration(c.AccessTokenTTL) * time.Second
}

func (c *Client) RefreshTokenTTLDuration() time.Duration {
	return time.Duration(c.RefreshTokenTTL) * time.Second
}

func (c *Client) VerifyRedirectURI(uri string) bool {
	ss := strings.Split(c.RedirectURIPrefixs, ",")
	for _, s := range ss {
		if strings.HasPrefix(uri, s) {
			return true
		}
	}
	return false
}

func (c *Client) VerifyScopesAllowed(scopes []string) bool {
	allowed := set.From(strings.Split(c.AllowedScopes, " "))
	return allowed.ContainsSlice(scopes)
}
