# List available recipes
default:
    @just --list

export PATH := `go env GOPATH` + "/bin:" + env_var('PATH')

# Caddy version to build
CADDY_VERSION := "v2.11.4"

# Build project with xcaddy
build:
    mkdir -p bin
    xcaddy build {{CADDY_VERSION}} --with github.com/charleshuang3/caddypaw=. --output bin/caddy




# Run linters
lint: lint-backend

# Lint backend code using golangci-lint
lint-backend:
    golangci-lint run ./...

# Run go mod tidy
tidy:
    go mod tidy

# Update go mod dependencies
update-go-deps:
    go get -u -t ./...
    @just tidy

# Update dependencies
update-deps: update-go-deps

# Run backend tests
test: test-backend

# Run backend tests
test-backend:
    go test -v ./...

# Format backend code
fmt: fmt-backend

# Format backend Go code using goimports
fmt-backend:
    goimports -w -local "github.com/charleshuang3/caddypaw" .

# Check formatting without modifying files
fmt-check: fmt-check-backend

# Check backend Go code formatting using goimports
fmt-check-backend:
    @test -z "$($(go env GOPATH)/bin/goimports -local github.com/charleshuang3/caddypaw -l . 2>/dev/null || goimports -local github.com/charleshuang3/caddypaw -l .)" || (echo "Unformatted Go files found:" && goimports -local github.com/charleshuang3/caddypaw -l . && exit 1)

# Clean build artifacts
clean:
    rm -rf bin

