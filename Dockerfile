# Stage 1: Build
FROM golang:1.24 AS builder

WORKDIR /app

# Copy go.mod and go.sum to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download

# Install xcaddy
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Copy the rest of the application source code
COPY . .

# Build Caddy with specified plugins
RUN xcaddy build v2.10.0 \
    --with github.com/caddy-dns/cloudflare \
    --with github.com/charleshuang3/caddypaw=. \
    --output bin/caddy

# Stage 2: Runtime
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk add --no-cache ca-certificates

WORKDIR /srv/caddy

# Copy the built Caddy binary from the builder stage
COPY --from=builder /app/bin/caddy /usr/bin/caddy

# See https://caddyserver.com/docs/conventions#file-locations for details
ENV XDG_CONFIG_HOME /config
ENV XDG_DATA_HOME /data

# Expose HTTP and HTTPS ports
EXPOSE 80 443

# Set the entrypoint to run Caddy
ENTRYPOINT ["caddy", "run", "--config", "/config/Caddyfile"]
