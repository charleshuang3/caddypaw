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
└── Justfile                 # Unified task entry: just lint / build / test / fmt / e2e
```

## Components

- **`pkg/caddypaw`** — Caddy v2 plugin acting as an authentication gateway in
  front of upstream apps. Supports basic auth, bearer tokens, and OIDC server
  cookies. Reports abusive IPs to the Authn firewall endpoint.
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
just e2e     # in-process E2E tests (test/e2e)
```

CI runs `goimports` check, `golangci-lint`, unit tests, and the E2E suite
on every push to `main` and every pull request.

## E2E Tests

The `test/e2e` suite runs the full chain in-process — a real Caddy instance
with the caddypaw plugin, a real authn server (SQLite in-memory, memory
firewall provider), and a mock upstream app — with **zero external
dependencies**: no network, no cloud credentials, no Docker, no hardware
firewalls.

```bash
just e2e          # or: go test -v ./test/e2e/...
```

Covered scenarios:

- **OIDC flow**: unauthenticated redirect → login page → password login →
  authorization-code exchange → cookie-authenticated request reaching the
  upstream.
- **Bearer token**: static token auth (missing / wrong / correct).
- **Firewall ban**: sliding-window error counting on `/logerr` triggers a
  ban recorded in the in-memory firewall; direct `/ban` endpoint as well.

The suite reuses the fixtures owned by each package: the GeoLite2 test
databases from `pkg/firewall/ipgeo/test-data` and the RSA test key pair from
`pkg/authn/testdata`.

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

For configuration examples, please refer to the `example/` directory.
