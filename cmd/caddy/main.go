// Command caddy is a convenience entry point that embeds the caddypaw plugin
// into a standard Caddy build. It is mainly used for local debugging and E2E
// tests; production builds should use xcaddy as documented in the README.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// Register caddypaw HTTP handlers and the global option app.
	_ "github.com/charleshuang3/caddypaw/pkg/caddypaw"
)

func main() {
	caddycmd.Main()
}
