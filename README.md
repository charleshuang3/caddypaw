# CaddyPAW Monorepo

CaddyPAW is a monorepo that combines authentication, firewall, and reverse-proxy
gateway components into a single Go module (`github.com/charleshuang3/caddypaw`).

## Repository Layout

```
caddypaw/
├── cmd/
│   ├── authn/               # Authn server entry point
│   └── caddy/               # Caddy binary entry point embedding the caddypaw plugin
├── pkg/
│   ├── caddypaw/            # Caddy plugin: authn gateway (basic auth, bearer token, server cookies/OIDC)
│   ├── authn/               # Authn service: OIDC/OAuth2 provider, storage, firewall handlers
│   └── firewall/            # Firewall integration: IP ban logic, RouterOS/OpenSense/pfSense backends,
│                           #   GeoIP, log exporters (GCP Cloud Logging, zerolog)
├── test/
│   └── e2e/                 # In-process E2E test suite (Caddy + Authn + mock firewall/upstream)
├── example/                 # Caddyfile and authn config examples
├── Dockerfile               # Caddy (caddypaw) image build
└── Justfile                 # Unified task entry: just lint / build / test / fmt
```

## Components

- **`pkg/caddypaw`** — Caddy v2 plugin acting as an authentication gateway in
  front of upstream apps. Supports basic auth, bearer tokens, and OIDC server
  cookies. Reports abusive IPs to the Authn firewall endpoint.
- **`pkg/waf`** — Web Application Firewall engine powered by Coraza v3 with
  embedded OWASP Core Rule Set (CRS 4.x). Supports standalone `paw_waf` directive
  and embedded `waf` block in `paw_auth`. Automatically reports triggered rule IDs
  to the Authn firewall for automated IP banning.
- **`pkg/authn`** — Standalone OIDC/OAuth2 authentication service built with
  Gin + Gorm (SQLite for testing, PostgreSQL in production). See
  [pkg/authn/README.md](pkg/authn/README.md).
- **`pkg/firewall`** — IP banning with sliding-window rate limiting, multiple
  firewall backends (RouterOS, OpenSense, pfSense), GeoIP lookups, and log
  exporters. See [pkg/firewall/README.md](pkg/firewall/README.md).

## Development

Common tasks are defined in the `Justfile`:

```bash
just lint    # golangci-lint
just build   # go build ./...
just test    # go test ./...
just fmt     # goimports
```

CI runs `goimports` check, `golangci-lint`, and the test suite (unit + E2E)
on every push to `main` and every pull request.

## E2E Tests

The `test/e2e` suite runs the full chain in-process — a real Caddy instance
with the caddypaw plugin, a real authn server (SQLite in-memory, memory
firewall provider), and a mock upstream app — with **zero external
dependencies**: no network, no cloud credentials, no Docker, no hardware
firewalls.

```bash
go test -v ./test/e2e/...
```

Covered scenarios:

- **OIDC flow**: unauthenticated redirect → login page → password login →
  authorization-code exchange → cookie-authenticated request reaching the
  upstream.
- **Bearer token**: static token auth (missing / wrong / correct).
- **Firewall ban**: sliding-window error counting on `/logerr` triggers a
  ban recorded in the in-memory firewall; direct `/ban` endpoint as well.
- **Standalone WAF protection & ban**: `paw_waf` blocks malicious requests
  (e.g., phase 2 rules) with 403 and reports `waf:<rule_id>` to `/logerr`,
  triggering automated firewall bans after exceeding the forgivable threshold.
- **Embedded WAF in auth gateway**: `paw_auth { waf { ... } }` blocks attack
  traffic before authentication logic / redirects run, and enforces WAF checks
  on bearer-token and cookie-authenticated routes.
- **OWASP CRS 4.x inspection**: verifies embedded OWASP CRS rule loading
  (`@coraza.conf-recommended`, `@crs-setup.conf.example`, `@owasp_crs/*.conf`)
  and detection of common attacks (e.g. SQL injection).

The suite reuses the fixtures owned by each package: the GeoLite2 test
databases from `pkg/firewall/ipgeo/test-data` and the RSA test key pair from
`pkg/authn/testdata`.

## WAF Protection

CaddyPAW provides integrated Web Application Firewall (WAF) capabilities
powered by [Coraza](https://coraza.io) v3 and the embedded [OWASP ModSecurity Core Rule Set (CRS) v4](https://coreruleset.org).

### Standalone WAF (`paw_waf`)

Use `paw_waf` as a standalone Caddy middleware directive to inspect requests
before they reach upstream services:

```caddyfile
{
	authn_yaml_file /path/to/authn.config.yaml
	order paw_waf before basic_auth
}

example.com {
	paw_waf {
		load_owasp_crs
		directives `
			Include @coraza.conf-recommended
			SecRuleEngine On
			Include @crs-setup.conf.example
			Include @owasp_crs/*.conf
			SecRule ARGS:attack "@streq 1" "id:1001,phase:2,deny,status:403"
		`
	}
	reverse_proxy 127.0.0.1:8080
}
```

### Embedded WAF in `paw_auth`

Add a `waf { ... }` block inside `paw_auth` to inspect requests before any
authentication redirects (e.g. OIDC login flow) or token validation take place:

```caddyfile
{
	authn_yaml_file /path/to/authn.config.yaml
	order paw_auth before basic_auth
}

app.example.com {
	paw_auth {
		server_cookies
		client_id client_id
		client_secret client_secret
		callback_url https://app.example.com/paw/callback
		roles admin
		waf {
			load_owasp_crs
			directives `
				Include @coraza.conf-recommended
				SecRuleEngine On
				Include @crs-setup.conf.example
				Include @owasp_crs/*.conf
			`
		}
	}
	reverse_proxy 127.0.0.1:8080
}
```

### OWASP CRS & Coraza Directives

- **`load_owasp_crs`**: Activates embedded OWASP CRS 4.x rules. You can reference:
  - `@coraza.conf-recommended` — recommended Coraza base configuration.
  - `@crs-setup.conf.example` — standard CRS initialization settings.
  - `@owasp_crs/*.conf` — CRS rules covering SQLi, XSS, RCE, protocol violations, etc.
- **Custom Directives**: Inline ModSecurity / Coraza SecRules (e.g., `SecRuleEngine On`, custom `SecRule` definitions).
- **Local File Includes**: Include external rule files on disk using `Include /path/to/custom-rules/*.conf`.
- **Request Body Buffering**: Coraza buffers request bodies up to `SecRequestBodyInMemoryLimit` in memory and spools larger bodies to temporary files (under `/tmp`). In containerized deployments, ensure `/tmp` has adequate storage.

### Automated Firewall Reporting & Banning

When a WAF rule triggers an interruption:
1. CaddyPAW immediately blocks the request with HTTP 403 (or the configured status code).
2. The client IP and triggered rule ID (`reason=waf:<rule_id>`) are reported asynchronously to the Authn server's `/logerr` endpoint.
3. The Authn sliding-window rate limiter records the violation and automatically issues a firewall ban (via RouterOS, OPNsense, pfSense, or memory provider) once the error threshold is exceeded.

## Installation

To build a Caddy binary with the CaddyPAW plugin, use the `xcaddy` tool
(installation instructions [here](https://github.com/caddyserver/xcaddy#install)):

```bash
# From a released version:
xcaddy build --with github.com/charleshuang3/caddypaw/pkg/caddypaw

# From a local checkout (development):
xcaddy build \
    --with github.com/charleshuang3/caddypaw/pkg/caddypaw \
    --replace github.com/charleshuang3/caddypaw=.
```

The `--with` flag names the *package* to import; `--replace` maps the owning
*module* to the local directory (which must contain `go.mod`). Alternatively,
build the debug entry point directly:

```bash
go build ./cmd/caddy
```

## Configuration

For configuration examples, please refer to the `example/` directory:
`Caddyfile` and `authn.config.yaml` are templates to adapt by hand, while
`docker-compose.yaml` is a complete Docker deployment.

### Docker

The example deployment runs both images on a bridge network with a pinned
subnet:

```bash
# Fill in example/docker/*.yaml and example/geoip first (see the comments).
docker compose -f example/docker-compose.yaml up -d
```

The gateway address is pinned and listed in the authn config's
`trusted_proxies`, so `ClientIP()` reports the real client IP to the firewall.
Neither authn port is published to the host: the OIDC port is reached through
Caddy, and the firewall handler port (`ban_handlers_port`) is unauthenticated
and must stay inside the network.
