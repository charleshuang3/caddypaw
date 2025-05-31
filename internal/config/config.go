package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"gopkg.in/yaml.v2"
)

type AuthnConfig struct {
	AuthURL            string `yaml:"auth_url" json:"auth_url"`
	TokenURL           string `yaml:"token_url" json:"token_url"`
	NonOIDCUserInfoURL string `yaml:"non_oidc_userinfo_url" json:"non_oidc_userinfo_url"`
	FirewallURL        string `yaml:"firewall_url" json:"firewall_url"`
	PublicKeyPEM       string `yaml:"public_key_pem" json:"public_key_pem"`
}

func LoadFromFile(path string) (*AuthnConfig, error) {
	res := &AuthnConfig{}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("fail to read file %q: %w", path, err)
	}

	err = yaml.Unmarshal(data, res)
	if err != nil {
		return nil, err
	}

	if res.AuthURL == "" {
		return nil, errors.New("AuthURL cannot be empty")
	}

	if res.TokenURL == "" {
		return nil, errors.New("TokenURL cannot be empty")
	}

	if res.NonOIDCUserInfoURL == "" {
		return nil, errors.New("NonOIDCUserInfoURL cannot be empty")
	}

	if res.FirewallURL == "" {
		return nil, errors.New("FirewallURL cannot be empty")
	}

	_, err = jwk.ParseKey([]byte(res.PublicKeyPEM), jwk.WithPEM(true))
	if err != nil {
		return nil, fmt.Errorf("fail to parse public key: %w", err)
	}

	return res, nil
}

func (c *AuthnConfig) GetPublicKey() jwk.Key {
	key, _ := jwk.ParseKey([]byte(c.PublicKeyPEM), jwk.WithPEM(true))
	// LoadFromFile() already verify the key is valid.

	return key
}
