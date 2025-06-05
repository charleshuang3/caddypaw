# CaddyPAW

CaddyPAW is a Caddy plugin designed for authentication and firewall capabilities.

## Summary

CaddyPAW integrates with `github.com/charleshuang3/authn` to provide:

- **OAuth/OIDC Client:** Acts as an OAuth/OIDC client and stores JWT tokens for authentication state using server cookies. It supports setting a callback URL to your application's login callback URL for OIDC login flows.
- **Firewall Integration:** Integrates with a firewall to ban IP addresses when attacks are detected.

## Installation

To install the CaddyPAW plugin, you can use the `xcaddy` tool. If you don't have `xcaddy` installed, you can follow the instructions [here](https://github.com/caddyserver/xcaddy#install).

Once you have `xcaddy`, you can build Caddy with the CaddyPAW plugin by running:

```bash
xcaddy build --with github.com/charleshuang3/caddypaw
```

This will produce a new Caddy binary that includes the CaddyPAW plugin.

## Configuration

For configuration examples, please refer to the `example/` directory.
