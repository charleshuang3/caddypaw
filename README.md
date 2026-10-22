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
  on bearer-token and cookie-authenticated routes. The optional `after_auth`
  mode (`detect_only` / `phase1_only` / `skip`) relaxes inspection for
  authenticated requests only; public URLs are always inspected in blocking
  mode.
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
		preset default
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
			preset default
		}
	}
	reverse_proxy 127.0.0.1:8080
}
```

#### Post-authentication modes (`after_auth`)

By default the embedded WAF runs *before* authentication, so it also inspects
requests that end up with a 401 or a login redirect. That is the safest default,
but it means a legitimate authenticated client can still be blocked by a false
positive — a common annoyance for WebDAV, where large binary uploads and XML
multipart bodies are hard for generic CRS rules to judge.

`after_auth` makes the WAF's behaviour depend on the authentication result. The
rule set is unchanged; only what happens *after* `paw_auth` authenticated the
request differs.

```caddyfile
dav.example.com {
	paw_auth {
		basic_auth
		client_id webdav
		client_secret client_secret
		roles admin
		waf {
			preset default
			after_auth detect_only
		}
	}
	reverse_proxy 127.0.0.1:8081
}
```

| Request | `block` (default) | `detect_only` | `phase1_only` | `skip` |
| --- | --- | --- | --- | --- |
| Unauthenticated, rule matched | blocked + reported (1 pt) | **reported only**, still gets 401/302 (1 pt) | **reported only**, still gets 401/302 (1 pt) | **reported only**, still gets 401/302 (1 pt) |
| Unauthenticated, rule matched and password rejected | blocked + reported (1 pt; authentication never runs) | **reported only**, still gets 401 (2 pts) | **reported only**, still gets 401 (2 pts) | **reported only**, still gets 401 (2 pts) |
| Unauthenticated, no rule matched | rejected password reported as `basic_auth: invalid credentials` (1 pt); no credentials not reported (0 pts) | same | same | same |
| `public_urls` match | blocked + reported | blocked + reported | blocked + reported | blocked + reported |
| Authenticated, URI/header match (phase 1) | blocked + reported (1 pt) | **reported only** (0 pts) | blocked + reported (1 pt) | not inspected |
| Authenticated, body match (phase 2) | blocked + reported (1 pt) | **reported only** (0 pts) | not inspected | not inspected |

The points in parentheses are what the request spends from the per-IP budget (see
[Ban threshold](#ban-threshold)); they never change the response the client sees.

`block` is the default and is also what an omitted `after_auth` means, so write
`after_auth block` or leave the option out entirely.

A credential that was **presented and rejected** is reported in **every** mode,
including `block`: a wrong password never trips a WAF rule, so without it password
brute forcing would be invisible to the firewall. A request that presents **no**
credentials at all is *not* reported: that is what every browser, health check,
uptime probe and WebDAV client sends before it knows a protected path exists.
`server_cookies` keeps its specific reasons (`invalid token on path: …`,
`callback: …`); a plain login redirect (302) is normal user traffic and is never
counted.

- **`detect_only`** — authenticated traffic is still fully inspected, and every
  match is logged (`waf rule matched on authenticated request ...`) and reported
  to `/logerr` as `waf:<rule_id>`, but nothing is blocked. Matches on
  authenticated requests are reported with `count=false`, so they appear in the
  firewall log without ever contributing to a ban — tuning rules can never lock
  a legitimate client out. Use it to collect the real rule IDs that trip your
  application before tuning them away.
- **`phase1_only`** — authenticated requests are checked on URI and headers
  only, so bodies are never buffered. Violations still block. This is the
  cheapest option that keeps detection: ideal for upload-heavy endpoints.
- **`skip`** — no WAF evaluation for authenticated requests at all.

Three consequences are worth stating explicitly:

1. In any `after_auth` mode, authentication runs *before* the WAF, so a client
   without credentials receives the normal 401 challenge / login redirect
   instead of a WAF 403, and the WAF verdict is applied afterwards. This avoids
   one classic pitfall: a WAF 403 preempting the 401 would deny the client the
   `WWW-Authenticate` challenge it needs to retry with credentials.
2. Unauthenticated requests that **do** trip a rule are still inspected, logged
   and reported as `waf:<rule_id>` — they just keep their 401/302 status. That
   keeps the ban pipeline fed for the most suspicious traffic (unauthenticated
   probes) without breaking clients, and such reports **do** count towards a
   ban: the request was not served. Each request produces **exactly one**
   report, but that report carries every signal the request produced (see
   [Ban threshold](#ban-threshold)), so a request that both fails authentication
   and trips a rule costs two points instead of one.
3. `detect_only` still reads and buffers request bodies; it only removes the
   blocking. If the motivation is memory/CPU on large uploads, use
   `phase1_only` or `skip`: those two never buffer a body, for authenticated and
   unauthenticated requests alike. In `phase1_only` and `skip`, unauthenticated
   probes are still inspected through phase 1 only, so a body-level rule can
   never match them. Only `detect_only` builds a second, detection-only engine
   next to the blocking one (which keeps guarding `public_urls`), so expect
   roughly double the rule-compilation memory at startup only in that mode.

### Ban threshold

Reports from all sources share one per-IP budget (`pkg/firewall`).
`forgivable.count` is a budget in **points**, not a number of events: each report
spends its weight, and the IP is banned once a report no longer fits in the budget
for `forgivable.duration_in_minute` (defaults: **3 points / 10 minutes → 10 minute
ban**).

| Signal | Weight |
| --- | --- |
| WAF rule matched, request refused (`waf:<id>`) | 1 |
| Rejected password (`basic_auth: invalid credentials`) | 1 |
| Invalid session token or broken login callback (`invalid token on path: …`, `callback: …`) | 1 |
| A request refused **and** its password rejected (one report) | 2 |
| Authenticated request matched in `detect_only` | 0 (observed, never bans) |
| No credentials at all | not reported |

One point is the cost of one independent signal, so the default budget of 3 points
bans a plain violation on the fourth report — the same threshold as before weights
existed — and a corroborated violation on the second.

A rejected password is the only signal that proves intent: the client typed or
replayed a secret and got it wrong, and no WAF rule can produce that evidence. A
broken login flow (expired or rotated session token, failed callback) weighs the
same single point: it is far more often a client bug than an attack, and treating
it as intent would ban every session whenever the authn signing key is rotated.

Weights add up, but a request is still reported **once**: the reasons are joined
(`waf:949110 | basic_auth: invalid credentials`) so the ban log shows every
signal, and the weights are summed (`/logerr?...&weight=2`). A request that both
guesses a password and carries a malicious payload therefore spends 2 points at
once — two independent signals are much stronger evidence than either alone —
while a browser that merely opens a protected page spends nothing, and one that
retries with a stale password spends 1 point per attempt.

A weight is never partially accounted: if the remaining budget cannot cover it,
the IP is banned rather than having the event rounded down. Conversely, a single
report can never ban an IP on its own — the weight is capped at the budget — so
banning always requires at least two reports within the window, and one
malicious-looking request (or one forged `/logerr` call) cannot ban an IP by
itself.

Two signals can only corroborate each other when both are actually evaluated. In
the default `block` mode the WAF refuses the request before authentication runs,
so a blocked request always weighs 1 — that is not a limitation worth working
around, since the request is already denied. Set `after_auth` if you want
authentication to run first and the two signals to add up.

The counter is bypassed in exactly one case: matches reported as *observed*
(`/logerr?count=false`), which are written to the firewall log but consume no
allowance and never ban. Only `detect_only` matches on **authenticated** requests
use it, on the grounds that a request we served successfully should not be able
to get its own client banned. A match on an **unauthenticated** request does
count: the request was refused, so it is a real violation.

`after_auth` only exists inside `paw_auth`; the standalone `paw_waf` directive
has no authentication context and always behaves as `block`. Setting it there
logs a startup warning and the value is ignored.

### OWASP CRS & Coraza Directives

- **`preset default`**: Shorthand for the recommended full configuration — loads the embedded Coraza recommended base config plus the complete OWASP CRS (`load_owasp_crs` + the four standard `Include` lines). Mutually exclusive with `directives`. To tune CRS settings (e.g. paranoia level), keep using explicit `directives` with `SecAction setvar` overrides.
- **`after_auth`**: Selects how `paw_auth` treats requests that authenticated successfully (`detect_only`, `phase1_only`, `skip`). It is a runtime policy, not a rule set, and therefore combines with any `preset` or `directives` value. Unset means `block`. See [Post-authentication modes](#post-authentication-modes-after_auth).
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
