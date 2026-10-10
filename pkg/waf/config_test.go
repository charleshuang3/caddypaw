package waf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		wantError string
	}{
		{
			name: "empty directives",
			cfg: Config{
				Directives: "   ",
			},
			wantError: "waf directives cannot be empty",
		},
		{
			name: "owasp_crs without load_owasp_crs",
			cfg: Config{
				LoadOWASPCRS: false,
				Directives:   "Include @owasp_crs/*.conf",
			},
			wantError: "directives reference OWASP CRS rules but load_owasp_crs is false",
		},
		{
			name: "crs-setup without load_owasp_crs",
			cfg: Config{
				LoadOWASPCRS: false,
				Directives:   "Include @crs-setup.conf.example",
			},
			wantError: "directives reference OWASP CRS rules but load_owasp_crs is false",
		},
		{
			name: "custom directives valid",
			cfg: Config{
				Directives: "SecRuleEngine On",
			},
			wantError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfig_BuildCorazaConfig_MergeFS(t *testing.T) {
	// Create a temporary local rule file
	tempDir := t.TempDir()
	localRuleFile := filepath.Join(tempDir, "local-rule.conf")
	err := os.WriteFile(localRuleFile, []byte(`SecRule ARGS:local "@streq blocked" "id:9999,phase:1,deny,status:403"`), 0o600)
	require.NoError(t, err)

	cfg := &Config{
		LoadOWASPCRS: true,
		Directives: `
Include @coraza.conf-recommended
SecRuleEngine On
Include @crs-setup.conf.example
Include ` + localRuleFile + `
`,
	}

	logger := zaptest.NewLogger(t)
	corazaCfg, err := cfg.BuildCorazaConfig(logger)
	require.NoError(t, err)
	require.NotNil(t, corazaCfg)
}

func TestConfig_UnmarshalCaddyfile(t *testing.T) {
	caddyfileInput := `waf {
		load_owasp_crs
		directives "SecRuleEngine On"
	}`

	d := caddyfile.NewTestDispenser(caddyfileInput)
	d.Next() // consume "waf"

	var cfg Config
	err := cfg.UnmarshalCaddyfile(d)
	require.NoError(t, err)
	assert.True(t, cfg.LoadOWASPCRS)
	assert.Equal(t, "SecRuleEngine On", cfg.Directives)
}

func TestConfig_UnmarshalCaddyfile_Invalid(t *testing.T) {
	caddyfileInput := `waf {
		unknown_directive
	}`

	d := caddyfile.NewTestDispenser(caddyfileInput)
	d.Next() // consume "waf"

	var cfg Config
	err := cfg.UnmarshalCaddyfile(d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unrecognized waf directive")
}
