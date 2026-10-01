package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"

	"github.com/charleshuang3/caddypaw/pkg/authn/gormw"
	middleware "github.com/charleshuang3/caddypaw/pkg/authn/handlers/firewall"
	"github.com/charleshuang3/caddypaw/pkg/authn/handlers/oidc"
)

func TestLoadConfigSuccess(t *testing.T) {
	// Create a temporary directory
	tmpDir := t.TempDir()

	// Create a temporary config file path
	tmpConfigFile := filepath.Join(tmpDir, "config.yaml")

	// Sample valid configuration data
	sampleConfig := &Config{
		Port:            8080,
		BanHandlersPort: 8081,
		GinMode:         "debug",
		OIDC: oidc.OIDCProviderConfig{
			Title:         "Test OIDC Provider",
			PrivateKeyPEM: "testprivatekeypem",
			Issuer:        "http://localhost:8080",
			SSO: oidc.SSOConfig{
				Google: oidc.GoogleLogin{
					ClientID:     "testclientid",
					ClientSecret: "testclientsecret",
					RedirectURI:  "http://localhost:8080/callback",
				},
			},
		},
		DB: gormw.Config{
			DSN:                  "testdsn",
			DisableAutomaticPing: false,
			MaxOpenConns:         10,
			MaxIdleConns:         5,
			LogLevel:             2, // gormlog.Error
		},
		Firewall: middleware.FirewallConfig{
			Provider:         "ros",
			ProviderIP:       "192.168.1.1",
			ProviderUser:     "admin",
			ProviderPassword: "password",
			ListUUID:         "12345",
			Whitelist:        []string{"192.168.1.1", "192.168.1.2"},
			BanMinutes:       10,
			Forgivable: middleware.ForgivableError{
				DurationInMinute: 10,
				Count:            3,
			},

			CityDBFile:        "/path/to/city.mmdb",
			UpdatedCityDBFile: "/path/to/updated_city.mmdb",
			ASNDBFile:         "/path/to/asn.mmdb",
			UpdatedASNDBFile:  "/path/to/updated_asn.mmdb",

			GoogleKeyFile:   "/path/to/key.json",
			GoogleProjectID: "project-id",
		},
	}

	// Marshal the sample config to YAML
	configData, err := yaml.Marshal(&sampleConfig)
	assert.NoError(t, err)

	// Write the YAML data to the temporary file
	err = os.WriteFile(tmpConfigFile, configData, 0644)
	assert.NoError(t, err)

	// Load the config from the temporary file
	loadedConfig := LoadConfig(tmpConfigFile)

	// Assert that the loaded config matches the sample config
	assert.NotNil(t, loadedConfig)
	assert.Equal(t, sampleConfig, loadedConfig)
}
