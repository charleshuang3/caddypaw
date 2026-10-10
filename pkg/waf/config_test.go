package waf

import (
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestPresetDefault(t *testing.T) {
	c := Config{Preset: "default"}
	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !c.LoadOWASPCRS {
		t.Fatal("preset default must enable LoadOWASPCRS")
	}
	for _, want := range []string{"@coraza.conf-recommended", "SecRuleEngine On", "@crs-setup.conf.example", "@owasp_crs/*.conf"} {
		if !strings.Contains(c.Directives, want) {
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
		{"preset with directives", Config{Preset: "default", Directives: "SecRuleEngine On"}},
	}
	for _, tt := range tests {
		if err := tt.cfg.Validate(); err == nil {
			t.Errorf("%s: expected error, got nil", tt.name)
		}
	}
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
