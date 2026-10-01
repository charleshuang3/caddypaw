# List available recipes
default:
    @just --list

export PATH := `go env GOPATH` + "/bin:" + env('PATH')

# Caddy version to build
CADDY_VERSION := "v2.11.4"

# Build project with xcaddy
build:
    mkdir -p bin
    xcaddy build {{CADDY_VERSION}} --with github.com/charleshuang3/caddypaw=. --output bin/caddy

# Run linters using golangci-lint
lint:
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

# Run tests
test:
    go test -v ./...

# Format code
fmt:
    goimports -w -local "github.com/charleshuang3/caddypaw" .

# Clean build artifacts
clean:
    rm -rf bin
