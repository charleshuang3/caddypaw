package testapp

import "github.com/coreos/go-oidc/v3/oidc"

type idTokenInfo struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	Email     string   `json:"email"`
	Roles     string   `json:"roles"`
	GoogleID  string   `json:"google_id"`
	Picture   string   `json:"picture"`
	Name      string   `json:"name"`
	Scope     string   `json:"scope"`
}

func (s *idTokenInfo) readIDToken(idToken *oidc.IDToken) error {
	if err := idToken.Claims(s); err != nil {
		return err
	}

	s.Issuer = idToken.Issuer
	s.Subject = idToken.Subject
	s.Audience = idToken.Audience
	s.ExpiresAt = idToken.Expiry.Unix()
	s.IssuedAt = idToken.IssuedAt.Unix()

	return nil
}

type refreshTokenInfo struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	Scope     string   `json:"scope"`
}

func (s *refreshTokenInfo) readRefreshToken(refreshToken *oidc.IDToken) error {
	if err := refreshToken.Claims(s); err != nil {
		return err
	}
	s.Issuer = refreshToken.Issuer
	s.Subject = refreshToken.Subject
	s.Audience = refreshToken.Audience
	s.ExpiresAt = refreshToken.Expiry.Unix()
	s.IssuedAt = refreshToken.IssuedAt.Unix()

	return nil
}
