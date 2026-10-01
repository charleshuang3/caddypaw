# List available recipes
default:
    @just --list

export PATH := `go env GOPATH` + "/bin:" + env('PATH')

# Caddy version to build
CADDY_VERSION := "v2.11.4"

# Build all packages
build:
    go build -v ./...

# Build caddy binary with the caddypaw plugin using xcaddy
build-caddy:
    mkdir -p bin
    xcaddy build {{CADDY_VERSION}} \
        --with github.com/charleshuang3/caddypaw/pkg/caddypaw \
        --replace github.com/charleshuang3/caddypaw=. \
        --output bin/caddy

# Run linters using golangci-lint
lint:
    golangci-lint run ./...

# Run tests
test:
    go test -v ./...

# Run go mod tidy
tidy:
    go mod tidy

# Update go mod dependencies
update-go-deps:
    go get -u -t ./...
    @just tidy

# Update dependencies
update-deps: update-go-deps

# Format code with goimports
fmt:
    goimports -w -local "github.com/charleshuang3/caddypaw" .

# Check code formatting with goimports
fmt-check:
    @test -z "$(goimports -local "github.com/charleshuang3/caddypaw" -l .)" || (echo "Unformatted Go files found:" && goimports -local "github.com/charleshuang3/caddypaw" -l . && exit 1)

# Build authn Docker image
build-authn-image:
    docker build -t ghcr.io/charleshuang3/authn:main -f Dockerfile.authn .

# Build caddy Docker image
build-caddy-image:
    docker build -t ghcr.io/charleshuang3/caddypaw:main -f Dockerfile .

# Clean build artifacts
clean:
    rm -rf bin
