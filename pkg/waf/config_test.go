package waf

import (
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPresetDefault(t *testing.T) {
	c := Config{Preset: "default"}
	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !c.loadsOWASPCRS() {
		t.Fatal("preset default must mount the OWASP CRS filesystem")
	}
	directives, err := c.effectiveDirectives()
	if err != nil {
		t.Fatalf("effective directives: %v", err)
	}
	for _, want := range []string{"@coraza.conf-recommended", "SecRuleEngine On", "@crs-setup.conf.example", "@owasp_crs/*.conf"} {
		if !strings.Contains(directives, want) {
			t.Errorf("preset directives missing %q", want)
		}
	}
}

func TestPresetErrors(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"unknown preset", Config{Preset: "strict"}},
		{"unknown preset with directives", Config{Preset: "strict", Directives: "SecRuleEngine On"}},
	}
	for _, tt := range tests {
		if err := tt.cfg.Validate(); err == nil {
			t.Errorf("%s: expected error, got nil", tt.name)
		}
	}
}

// TestPresetWithDirectives checks that operator directives extend the preset:
// they come after the preset's base settings, so they can override them, and
// before the CRS rule files, so runtime exclusions are in place before the rules
// they tune.
func TestPresetWithDirectives(t *testing.T) {
	const extra = `SecRule REQUEST_URI "@beginsWith /api/" "id:20001,phase:1,pass,nolog,ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:json.prompt"`
	c := Config{Preset: "default", Directives: "\n\t" + extra + "\n"}
	require.NoError(t, c.Validate())

	directives, err := c.effectiveDirectives()
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(directives, defaultPresetBase), "preset base must come first")
	assert.True(t, strings.HasSuffix(directives, crsRulesInclude), "CRS rules must come last")
	base := strings.Index(directives, "id:10003")
	ext := strings.Index(directives, extra)
	rules := strings.Index(directives, crsRulesInclude)
	require.NotEqual(t, -1, ext, "operator directives missing")
	assert.Less(t, base, ext, "operator directives must follow the preset base")
	assert.Less(t, ext, rules, "operator directives must precede the CRS rules")
	assert.Equal(t, 1, strings.Count(directives, crsRulesInclude), "CRS rules must be included once")

	// Whitespace-only directives are the same as none.
	blank := Config{Preset: "default", Directives: " \n\t"}
	plain := Config{Preset: "default"}
	got, err := blank.effectiveDirectives()
	require.NoError(t, err)
	want, err := plain.effectiveDirectives()
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestPresetWithDirectivesCaddyfile(t *testing.T) {
	var c Config
	d := caddyfile.NewTestDispenser("waf {\n\tpreset default\n\tdirectives `SecRuleEngine DetectionOnly`\n}")
	d.Next() // consume the directive name, as handler wrappers do
	require.NoError(t, c.UnmarshalCaddyfile(d))
	assert.Equal(t, "default", c.Preset)
	assert.Equal(t, "SecRuleEngine DetectionOnly", c.Directives)
	require.NoError(t, c.Validate())
}

func TestPresetCaddyfile(t *testing.T) {
	for _, input := range []string{"waf {\n\tpreset default\n}", "paw_waf {\n\tpreset default\n}"} {
		var c Config
		d := caddyfile.NewTestDispenser(input)
		d.Next() // consume the directive name, as handler wrappers do
		if err := c.UnmarshalCaddyfile(d); err != nil {
			t.Fatalf("unmarshal %q: %v", input, err)
		}
		if c.Preset != "default" {
			t.Errorf("unmarshal %q: preset = %q", input, c.Preset)
		}
		if err := c.Validate(); err != nil {
			t.Errorf("validate %q: %v", input, err)
		}
	}
}

func TestAfterAuthCaddyfile(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		want        string
		expectError bool
	}{
		{"detect_only", "waf {\n\tpreset default\n\tafter_auth detect_only\n}", AfterAuthDetectOnly, false},
		{"phase1_only", "waf {\n\tpreset default\n\tafter_auth phase1_only\n}", AfterAuthPhase1Only, false},
		{"skip", "waf {\n\tpreset default\n\tafter_auth skip\n}", AfterAuthSkip, false},
		{"missing argument", "waf {\n\tpreset default\n\tafter_auth\n}", "", true},
		{"too many arguments", "waf {\n\tpreset default\n\tafter_auth skip skip\n}", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c Config
			d := caddyfile.NewTestDispenser(tt.input)
			d.Next() // consume the directive name, as handler wrappers do
			err := c.UnmarshalCaddyfile(d)
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if c.AfterAuth != tt.want {
				t.Errorf("after_auth = %q, want %q", c.AfterAuth, tt.want)
			}
			if err := c.Validate(); err != nil {
				t.Errorf("validate: %v", err)
			}
		})
	}
}

func TestAfterAuthValidate(t *testing.T) {
	for _, mode := range []string{AfterAuthBlock, AfterAuthDetectOnly, AfterAuthPhase1Only, AfterAuthSkip} {
		c := Config{Directives: "SecRuleEngine On", AfterAuth: mode}
		if err := c.Validate(); err != nil {
			t.Errorf("after_auth %q: unexpected error %v", mode, err)
		}
	}

	c := Config{Directives: "SecRuleEngine On", AfterAuth: "block_after_auth"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for unknown after_auth mode")
	}
}

// TestValidate_IsStateless guards the paw_auth provisioning path, which builds
// two WAF instances from one Config and therefore calls Validate twice (once per
// instance). Validation must not write anything back, otherwise the second call
// would see the preset expansion as operator directives and insert the whole
// preset again. Regression: the expansion used to be memoised into Directives.
func TestValidate_IsStateless(t *testing.T) {
	for _, mode := range []string{"", AfterAuthBlock, AfterAuthDetectOnly, AfterAuthPhase1Only, AfterAuthSkip} {
		t.Run("after_auth="+mode, func(t *testing.T) {
			c := &Config{Preset: "default", AfterAuth: mode}
			require.NoError(t, c.Validate())

			directives, err := c.effectiveDirectives()
			require.NoError(t, err)
			require.NotEmpty(t, directives)

			require.NoError(t, c.Validate(), "second Validate must not fail")
			again, err := c.effectiveDirectives()
			require.NoError(t, err)
			assert.Equal(t, directives, again, "expansion must be stable")
			assert.Empty(t, c.Directives, "Validate must not rewrite the config")
			assert.Equal(t, mode, c.AfterAuth, "the operator's value must be preserved")
			assert.True(t, c.loadsOWASPCRS())
		})
	}

	t.Run("directives config", func(t *testing.T) {
		c := &Config{Directives: "SecRuleEngine On"}
		require.NoError(t, c.Validate())
		require.NoError(t, c.Validate())
		directives, err := c.effectiveDirectives()
		require.NoError(t, err)
		assert.Equal(t, "SecRuleEngine On", directives)
		assert.False(t, c.loadsOWASPCRS())
	})

	t.Run("preset plus directives", func(t *testing.T) {
		const extra = "SecRuleEngine DetectionOnly"
		c := &Config{Preset: "default", Directives: extra}
		require.NoError(t, c.Validate())
		directives, err := c.effectiveDirectives()
		require.NoError(t, err)
		require.NoError(t, c.Validate(), "second Validate must not fail")
		again, err := c.effectiveDirectives()
		require.NoError(t, err)
		assert.Equal(t, directives, again, "expansion must be stable")
		assert.Equal(t, extra, c.Directives, "Validate must not rewrite the config")
		assert.Equal(t, 1, strings.Count(directives, crsRulesInclude))
	})
}

// TestAfterAuthBlockDefault makes sure the value the README table shows ("block")
// is accepted, and that an omitted value means the same thing without the config
// being rewritten behind the operator's back.
func TestAfterAuthBlockDefault(t *testing.T) {
	for _, mode := range []string{"", AfterAuthBlock} {
		c := Config{Directives: "SecRuleEngine On", AfterAuth: mode}
		require.NoError(t, c.Validate())
		assert.Equal(t, AfterAuthBlock, c.AfterAuthMode())
		assert.Equal(t, mode, c.AfterAuth, "Validate must not normalise the stored value")
	}

	var nilConfig *Config
	assert.Equal(t, AfterAuthBlock, nilConfig.AfterAuthMode())

	var parsed Config
	d := caddyfile.NewTestDispenser("waf {\n\tdirectives `SecRuleEngine On`\n\tafter_auth block\n}")
	d.Next()
	require.NoError(t, parsed.UnmarshalCaddyfile(d))
	require.NoError(t, parsed.Validate())
	assert.Equal(t, AfterAuthBlock, parsed.AfterAuthMode())
}
