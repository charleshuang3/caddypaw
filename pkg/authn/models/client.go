package models

import (
	"net/url"
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
	RedirectURIPrefixs string // comma separated registered redirect URIs
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

// VerifyRedirectURI reports whether uri is one of the registered redirect URIs
// of the client. A registered entry that omits the port matches any port,
// because home setups often run the gateway on a non-standard port.
func (c *Client) VerifyRedirectURI(uri string) bool {
	requested, err := url.Parse(uri)
	if err != nil || requested.Scheme == "" || requested.Host == "" {
		return false
	}

	for _, prefix := range strings.Split(c.RedirectURIPrefixs, ",") {
		registered, err := url.Parse(prefix)
		if err != nil || registered.Scheme == "" || registered.Host == "" {
			continue
		}

		if !strings.EqualFold(requested.Scheme, registered.Scheme) ||
			!strings.EqualFold(requested.Hostname(), registered.Hostname()) {
			continue
		}

		if port := registered.Port(); port != "" && port != requested.Port() {
			continue
		}

		if strings.HasPrefix(requested.EscapedPath(), registered.EscapedPath()) {
			return true
		}
	}

	return false
}

func (c *Client) VerifyScopesAllowed(scopes []string) bool {
	allowed := set.From(strings.Split(c.AllowedScopes, " "))
	return allowed.ContainsSlice(scopes)
}
