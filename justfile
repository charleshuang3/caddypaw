# Define the Caddy version to build
CADDY_VERSION := "v2.10.0"

# Define the Caddy build target directory
BUILD_DIR := "bin"

# Define the Caddy binary name
CADDY_BIN := BUILD_DIR + "/caddy"

# Define the config location
CADDYFILE := ".local/Caddyfile"

# Define env file
ENV_FILE := ".local/env"

# Define the list of Caddy plugins to include
# The 'github.com/caddy-dns/cloudflare' plugin is essential for Cloudflare DNS challenge.
CLOUDFLARE_PLUGIN := "github.com/caddy-dns/cloudflare"

# This project
CURRENT := "github.com/charleshuang3/caddypaw=."

# Default recipe: builds the Caddy binary
default: build

# Install dependencies recipe: installs xcaddy
install-deps:
    @echo "Installing xcaddy..."
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
    @echo "xcaddy installed."

# Build recipe: downloads Caddy and builds it with specified plugins
build:
    @echo "Building Caddy {{CADDY_VERSION}} with plugins..."
    # Create the build directory if it doesn't exist
    mkdir -p {{BUILD_DIR}}
    # Use 'xcaddy' to build Caddy with the specified version and plugins.
    xcaddy build {{CADDY_VERSION}} \
        --with {{CLOUDFLARE_PLUGIN}} \
        --with {{CURRENT}} \
        --output {{CADDY_BIN}}
    @echo "Caddy binary built at {{CADDY_BIN}}"

# Run recipe: executes the built Caddy binary
run:
    @echo "Running Caddy..."
    test -f {{ENV_FILE}} && \
    source {{ENV_FILE}} && \
    {{CADDY_BIN}} run --config {{CADDYFILE}}

# Clean recipe: removes the built Caddy binary and build directory
clean:
    @echo "Cleaning up build artifacts..."
    rm -rf {{BUILD_DIR}}
    @echo "Clean complete."
