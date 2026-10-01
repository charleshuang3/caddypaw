# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

CaddyPAW is a monorepo (single Go module `github.com/charleshuang3/caddypaw`) providing an authentication gateway stack for self-hosted home use:

- **`pkg/caddypaw`** — Caddy v2 plugin acting as an auth gateway in front of upstream apps. Registers the `paw_auth` HTTP handler directive and the `authn_yaml_file` global option. Three auth types: `basic_auth`, `server_cookies` (OIDC authorization-code flow), `bearer_token` (static token).
- **`pkg/authn`** — standalone OIDC/OAuth2 provider (Gin + Gorm, SQLite or PostgreSQL). Sign-in: local username/password, Google SSO, invitation-code signup. Also serves the firewall HTTP handlers (`/ban`, `/logerr`).
- **`pkg/firewall`** — IP banning library: sliding-window rate limiting, GeoIP lookups (MaxMind), backends for RouterOS / OPNsense / pfSense, plus an in-memory recorder (`pkg/firewall/memory`) used by tests and a `memory` provider that is **test-only**.
- **`cmd/authn`** — authn server entry point; **`cmd/caddy`** — plain Caddy binary embedding the plugin (for local debugging/E2E only; production uses xcaddy).
- **`test/e2e`** — in-process E2E suite: mock upstream + real authn (in-memory SQLite, `memory` firewall) + real Caddy, all on 127.0.0.1. Zero external dependencies.

Request flow being protected: client → Caddy (`paw_auth`) → upstream. On auth failures, the gateway reports IPs to authn's `/logerr`; authn counts errors per IP in a sliding window and bans repeat offenders through the configured firewall backend.

## Commands

```bash
just lint         # golangci-lint run ./... (must be clean)
just build        # go build ./...
just test         # go test ./... (includes ./test/e2e)
just e2e          # go test -v ./test/e2e/... only
just fmt          # goimports -w -local "github.com/charleshuang3/caddypaw" .
just fmt-check    # formatting gate used by CI
just build-caddy  # xcaddy build ... -> bin/caddy
just tidy         # go mod tidy
```

Before considering work done, run: `just lint && just build && just test && just fmt-check`.

`golangci-lint` and `goimports` are expected on PATH (`just` prepends `$(go env GOPATH)/bin`). Go toolchain: 1.27.1 (see `go.mod`). CI also pins these versions in `.github/workflows/test-on-push.yml` — keep them in sync when upgrading.

## Layout notes

- `pkg/caddypaw/config` holds the gateway-side authn YAML config; `pkg/authn/config` is the server-side config. Do not confuse them.
- Test fixtures have single owners; never copy them:
  - RSA test key pair: `pkg/authn/testdata/*.pem` (embedded). `pkg/caddypaw/testdata` re-exports it and generates the gateway YAML via `AuthnYAML(t)`.
  - GeoLite2 test DBs: `pkg/firewall/ipgeo/test-data/` (also used by E2E).
- `pkg/authn/manualtest` and `pkg/firewall/{opn,pf,gcplog}/manual_test` are manual harnesses requiring real hardware/credentials; they are excluded from normal test runs.
- Docker: `Dockerfile` (caddy image) and `Dockerfile.authn` both end with a `deploy` stage; `.github/workflows/docker.yml` builds them via a matrix on push to `main` only.

## Conventions

- Go code comments and commit messages in English; conventional-commit prefixes (`fix:`, `feat:`, `chore:`, ...).
- The authn server is deliberately not a full OIDC implementation and is not horizontally scalable (auth codes live in in-memory cache). Don't add complexity aimed at fixing that unless asked.
- Fatal config errors in `pkg/authn` use `zerolog.Fatal()` at validate/construct time — follow that pattern for new providers/config.
