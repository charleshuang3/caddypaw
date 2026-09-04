ARG GO_VERSION=1.27.1

# Stage 1: Build
FROM golang:${GO_VERSION}-alpine AS builder

ARG CADDY_VERSION=v2.11.4

WORKDIR /app

# Copy go.mod and go.sum to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download

# Install xcaddy
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Copy the rest of the application source code
COPY . .

# Build Caddy with specified plugins
RUN xcaddy build ${CADDY_VERSION} \
    --with github.com/caddy-dns/cloudflare \
    --with github.com/charleshuang3/caddypaw=. \
    --output bin/caddy

# Stage 2: Runtime
FROM alpine:latest AS deploy

# Install ca-certificates for HTTPS
RUN apk add --no-cache ca-certificates

WORKDIR /srv/caddy

# Copy the built Caddy binary from the builder stage
COPY --from=builder /app/bin/caddy /usr/bin/caddy

# See https://caddyserver.com/docs/conventions#file-locations for details
ENV XDG_CONFIG_HOME /config
ENV XDG_DATA_HOME /data

# Expose HTTP and HTTPS ports
EXPOSE 80 443 443/udp

# Set the entrypoint to run Caddy
ENTRYPOINT ["caddy", "run", "--config", "/config/Caddyfile"]
