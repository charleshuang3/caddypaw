---
name: project-update
description: >-
  Runbook for updating dependencies, toolchains, Docker base images, and GitHub
  Actions in the caddypaw repository. Use when the user asks to update project
  dependencies, upgrade Go/Caddy/Docker/CI versions, or perform a routine
  dependency audit and bump.
---

# Project Update Runbook

Use this workflow when updating Go dependencies, Caddy, runtime toolchains,
Dockerfiles, or GitHub Actions in the `caddypaw` repository.

Never edit `go.sum` by hand.

## 1. Go & Caddy Dependencies

1. **Check current & outdated direct dependencies**:
   ```bash
   go list -u -m -f '{{if and (not .Indirect) .Update}}{{.Path}}: {{.Version}} -> {{.Update.Version}}{{end}}' all
   ```
2. **Update Go dependencies**:
   - Routine minor/patch/compatible updates:
     ```bash
     just update-go-deps
     ```
     (`just update-go-deps` runs `go get -u -t ./...` and `just tidy`.)
   - Targeted or major version bumps:
     ```bash
     go get <pkg>@<version>
     just tidy
     ```
3. **Keep Caddy version aligned**:
   - When `github.com/caddyserver/caddy/v2` in `go.mod` is updated, update
     `CADDY_VERSION` to match in both:
     - `Justfile` (`CADDY_VERSION := "vX.Y.Z"`)
     - `Dockerfile` (`ARG CADDY_VERSION=vX.Y.Z`)
4. **Check for Go vulnerabilities**:
   ```bash
   go run golang.org/x/vuln/cmd/govulncheck@latest ./...
   ```
5. **Check Go toolchain version**:
   - Check the `go X.Y.Z` directive in `go.mod`.
   - Keep the Go version aligned across `go.mod`, `Dockerfile`,
     `Dockerfile.authn`, `.github/workflows/test-on-push.yml`, and `AGENTS.md`.

## 2. Dockerfiles & Base Images

Inspect and update both Dockerfiles:

- `Dockerfile`:
  - `ARG GO_VERSION=<ver>` (`FROM golang:${GO_VERSION}-alpine AS builder`)
  - `ARG CADDY_VERSION=v<ver>`
  - `FROM alpine:latest AS deploy`
- `Dockerfile.authn`:
  - `ARG GO_VERSION=<ver>` (`FROM golang:${GO_VERSION}-alpine AS builder`)
  - `FROM alpine:latest AS deploy`

Checklist:
- Verify the latest stable tags for `golang:*-alpine` and `alpine:*`.
- Ensure `GO_VERSION` matches across `Dockerfile`, `Dockerfile.authn`, `go.mod`,
  `.github/workflows/test-on-push.yml`, and `AGENTS.md`.
- Ensure `CADDY_VERSION` in `Dockerfile` matches `Justfile` and `go.mod`.
- Build both images locally to verify:
  ```bash
  just build-caddy-image
  just build-authn-image
  ```

## 3. GitHub Actions & CI-Installed Tooling

Inspect all workflow files under `.github/workflows/` (`test-on-push.yml`,
`docker.yml`) and `.github/dependabot.yml`.

1. **CI-installed tool & runtime versions** (`.github/workflows/test-on-push.yml` `env:`):
   - `GO_VERSION`
   - `GOIMPORTS_VERSION` (`golang.org/x/tools/cmd/goimports@...`)
   - `GOLANGCI_LINT_VERSION`
2. **GitHub Action versions**:
   - `.github/workflows/test-on-push.yml`:
     - `actions/checkout`
     - `actions/setup-go`
   - `.github/workflows/docker.yml`:
     - `actions/checkout`
     - `docker/login-action`
     - `docker/metadata-action`
     - `docker/build-push-action`
     - `actions/attest-build-provenance`
   - Check latest action releases with `gh`:
     ```bash
     for repo in \
       actions/checkout \
       actions/setup-go \
       docker/login-action \
       docker/metadata-action \
       docker/build-push-action \
       actions/attest-build-provenance
     do
       tag=$(gh api "repos/$repo/releases/latest" --jq '.tag_name')
       echo "$repo: $tag"
     done
     ```

## 4. Verification

Run the local verification suite after all updates:

```bash
just fmt && just lint && just build && just test && just test-race && just fmt-check
```

If `CADDY_VERSION` or Caddy plugin code changed, also verify the xcaddy build:

```bash
just build-caddy
```

If Dockerfiles were modified, also build the images:

```bash
just build-caddy-image && just build-authn-image
```

Check `git status` and `git diff` to verify only expected files changed, and
commit using conventional commits (e.g., `build(deps): ...` or `ci: ...`).
