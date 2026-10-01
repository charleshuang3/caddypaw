package caddypaw

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"go.uber.org/zap"

	"github.com/charleshuang3/caddypaw/internal/config"
)

const (
	globalOptionAppName              = "paw_global_option"
	globalOptionKeyAuthnYAMLFilePath = "authn_yaml_file"
)

func init() {
	caddy.RegisterModule(globalOptionModule{})
	httpcaddyfile.RegisterGlobalOption(globalOptionKeyAuthnYAMLFilePath, parseGlobalOptionAuthnYAMLFilePath)
}

type globalOptionModule struct {
	AuthnConfig *config.AuthnConfig `json:"authn_yaml_file"`

	publicKey jwk.Key
	logger    *zap.Logger
}

// Start implements caddy.App.
func (g *globalOptionModule) Start() error {
	return nil
}

// Stop implements caddy.App.
func (g *globalOptionModule) Stop() error {
	return nil
}

// CaddyModule implements caddy.Module.
func (g globalOptionModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  globalOptionAppName,
		New: func() caddy.Module { return new(globalOptionModule) },
	}
}

// Provision implements caddy.Provisioner.
func (g *globalOptionModule) Provision(ctx caddy.Context) error {
	g.logger = ctx.Logger(g)
	g.logger.Info("provisioning app instance", zap.String("name", globalOptionAppName))

	g.publicKey = g.AuthnConfig.GetPublicKey()

	return nil
}

func (g *globalOptionModule) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	// read the yaml file path.
	if !d.NextArg() {
		return d.ArgErr()
	}
	p := d.Val()

	// load config from file.
	conf, err := config.LoadFromFile(p)
	if err != nil {
		return err
	}

	g.AuthnConfig = conf

	return nil
}

func parseGlobalOptionAuthnYAMLFilePath(d *caddyfile.Dispenser, _ any) (any, error) {
	g := &globalOptionModule{}
	err := g.UnmarshalCaddyfile(d)
	if err != nil {
		return nil, err
	}

	return httpcaddyfile.App{
		Name:  globalOptionAppName,
		Value: caddyconfig.JSON(g, nil),
	}, nil
}

var (
	// Interface guards
	_ caddy.Provisioner     = (*globalOptionModule)(nil)
	_ caddy.Module          = (*globalOptionModule)(nil)
	_ caddy.App             = (*globalOptionModule)(nil)
	_ caddyfile.Unmarshaler = (*globalOptionModule)(nil)
)
