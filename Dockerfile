# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
FROM golang:1.27-alpine AS build

WORKDIR /src

# go.sum lists golang.org/x/oauth2, which is a test-only dependency of
# internal/integration. It is never linked into the binary built below.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY cmd/ cmd/
COPY internal/ internal/

# CGO_ENABLED=0 is what makes the binary runnable FROM scratch: it selects Go's
# pure-Go net and user resolvers instead of linking against the host libc.
# -trimpath and the empty buildid keep the build reproducible.
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -buildvcs=false \
      -ldflags="-s -w -buildid=" \
      -o /out/strava-auth-proxy \
      ./cmd/strava-auth-proxy

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
FROM scratch

# The proxy makes outbound HTTPS calls to Strava, so it needs a trust store.
# scratch has none; this is the one thing that must be carried over.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

COPY --from=build /out/strava-auth-proxy /usr/local/bin/strava-auth-proxy

# Numeric UID/GID: scratch has no /etc/passwd to resolve a name against.
# 65532 is the conventional "nonroot" id. The process never writes to disk, so
# the image carries no writable directory and the filesystem can be read-only.
USER 65532:65532

# Documentation only — the ports actually bound come from LISTEN_ADDR and
# ADMIN_ADDR. ADMIN_ADDR defaults to loopback and is deliberately not published.
EXPOSE 8443

# There is no shell in this image; the binary probes its own admin listener.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/strava-auth-proxy", "-healthcheck"]

ENTRYPOINT ["/usr/local/bin/strava-auth-proxy"]
