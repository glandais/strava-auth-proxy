# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A reverse proxy that impersonates Strava's OAuth surface. Callers authenticate with **virtual
client credentials** issued by this proxy; the proxy validates them and substitutes the **real**
Strava application credentials on the upstream leg, so the real secret never leaves the process.
Everything under `/api/v3/*` is passed through to Strava untouched. The point is that an existing
Strava client can swap `https://www.strava.com` for this proxy's base URL and keep working.

`docs/DESIGN.md` is authoritative for behaviour; `docs/STRAVA-CONTRACT.md` records the real Strava
wire contract (including which parts were verified live and which are still assumptions).
`README.md` is the operator-facing config reference — don't duplicate it here.

## Commands

```sh
go build ./...
go vet ./...
go test ./...
go test -race -count=1 ./...

go test ./internal/oauth/ -run TestCallback          # one package, one test
go test -fuzz FuzzOpen -fuzztime 30s ./internal/seal/ # envelope parser fuzzing
go test ./internal/fault/ -update                     # rewrite golden bodies in testdata/
```

Run it locally (plain HTTP is refused unless `DEV_ALLOW_HTTP=true`):

```sh
STRAVA_CLIENT_ID=12345 STRAVA_CLIENT_SECRET=fake \
PROXY_PUBLIC_URL=https://proxy.example \
PROXY_STATE_KEYS="k1=$(head -c32 /dev/urandom | xxd -p -c64)" \
PROXY_CLIENTS_FILE=./clients.example.json \
LISTEN_ADDR=127.0.0.1:8443 ADMIN_ADDR=127.0.0.1:9090 DEV_ALLOW_HTTP=true \
go run ./cmd/strava-auth-proxy
```

`SIGHUP` reloads the config (validate-then-swap; the old config stays live if the new one is
invalid). Admin port serves `/healthz`, `/readyz` and expvar `/metrics`.

Docker (`.env` and `clients.json` are git-ignored; copy the committed `.example` templates):

```sh
docker compose up -d --build
docker compose kill -s HUP proxy    # reload clients.json without downtime
```

## Architecture

### The two sealed envelopes

The service stores **nothing** — no database, no session store, no token cache. That is possible
because all flow context rides in HMAC-sealed envelopes minted by `internal/seal`, formatted
`kid.base64url(flate(json)).base64url(HMAC-SHA256)`:

- **Packed state** (`seal.DomainState`) is the `state` sent to Strava. It seals the virtual
  `client_id`, the caller's original `redirect_uri`, and the caller's own `state`.
- **Wrapped code** (`seal.DomainCode`) is the `code` handed back to the caller. It seals the
  virtual `client_id` plus Strava's raw authorization code.

The domain prefix is part of the MAC input, so a state token can never verify as a code token —
type confusion is rejected cryptographically, before any parsing. `Ring.Open`'s step order is
security-critical and commented as such: split → kid lookup → `hmac.Equal` → inflate → unmarshal →
`iat` window. Never move payload interpretation above the MAC check.

An interposed `/oauth/callback` is unavoidable: Strava only redirects to the real app's registered
Authorization Callback Domain, so the proxy registers its own domain and re-redirects to the
virtual client's `redirect_uri` (re-validated against the *current* config, since a SIGHUP may have
landed mid-flow).

### Two rules that shape every handler

Both are documented at the top of `internal/oauth/handler.go` and are the reason to resist
"improving" the handlers:

1. **Validate only what the proxy must.** Only the virtual `client_id` and the `redirect_uri` are
   checked locally, because they gate the redirect. `scope`, `response_type`, `approval_prompt`,
   `grant_type` and every unknown parameter are forwarded verbatim so Strava emits its own canonical
   errors. Adding a local validation adds a contract-divergence point.
2. **Relay Strava verbatim.** `Handler.relay` streams the upstream status and body byte-for-byte and
   copies only `Content-Type`/`Content-Length`. Never re-marshal a token response — undocumented
   fields and the athlete object must survive. Never parse, log or store access/refresh tokens.

Token exchanges make exactly **one** upstream attempt: authorization codes are single-use, so a
retry burns the code. Don't add retries or a circuit breaker.

### Wiring details that are easy to break

- **`config` and `seal` are deliberately decoupled** — neither imports the other. `config.StateKey`
  is converted to `seal.Key` at the wiring layer. `oauth.Handler.Ring` left nil means the ring is
  derived from the live config on every request, so a SIGHUP that rotates keys takes effect
  immediately; setting it explicitly pins the ring (tests do this).
- **Route precedence**: `POST /api/v3/oauth/token` is registered as an exact pattern in
  `oauth.Handler.Register` so `ServeMux`'s most-specific-pattern rule makes it beat the `/api/v3/`
  reverse-proxy catch-all registered in `main`. `cmd/.../main_test.go` guards this.
- The security headers (`Referrer-Policy: no-referrer`, `Cache-Control: no-store`) wrap **only the
  `/oauth/*` surface**, not proxied API responses.
- The HTTP server sets `ReadHeaderTimeout` and `IdleTimeout` but deliberately **no `WriteTimeout`**,
  so long `/api/v3` streams and uploads survive.
- `upstream.NewTransport` sets `DisableCompression: true` on purpose: the caller's own
  `Accept-Encoding` is forwarded and gzip bodies pass through still-compressed. The reverse proxy
  uses the `Rewrite` hook, strips inbound `X-Forwarded-*`/`Forwarded`, and never calls
  `SetXForwarded`.
- `internal/fault` is the single source of every proxy-minted error body, golden-tested under
  `internal/fault/testdata/`. Add error cases there, not inline in handlers.

### Container image

`FROM scratch`, so two things must hold or the image breaks in ways the Go tests cannot catch:
the build must stay `CGO_ENABLED=0` (pure-Go net/user resolvers, no libc to link against), and
`/etc/ssl/certs/ca-certificates.crt` must keep being copied from the build stage — without it every
outbound HTTPS call to Strava fails at handshake. There is no shell, so `HEALTHCHECK` invokes
`strava-auth-proxy -healthcheck`, which probes `/healthz` on `ADMIN_ADDR` (see `healthcheck.go`);
that is what lets the admin listener stay bound to loopback.

### Invariants worth re-checking after any edit

No token is ever stored, cached or logged. `Secret.Reveal()` has exactly three legitimate call
sites (the two outbound Strava legs plus hashing at config load) — grep it. Upstream paths are
package constants and the host always comes from config, never from request input (non-SSRF by
construction). `redirect_uri` matching is exact string equality. No error path on `/oauth/authorize`
or `/oauth/callback` may redirect; they render a page. There is no `InsecureSkipVerify` code path,
and a test greps the source to keep it that way.

### Testing

`internal/fakestrava` is a configurable httptest double of the real Strava API (single-use codes,
granted-scope subsets, injectable errors, hangs, gzip/streaming/rate-limit endpoints, full request
recording). `internal/integration` stands up the real handler stack against it and drives complete
browser flows, including a **drop-in proof** that runs `golang.org/x/oauth2` unmodified against the
proxy, and a **secret-leak sweep** asserting the sentinel secret never appears in any captured
response or log record.

Known gap: `internal/integration/harness_test.go` re-implements ~15 lines of `main`'s wiring
(`publicHandler`, `oauthSurfaceHeaders`) because `package main` is unimportable, so changes to
main's wiring are not automatically covered. Update both.

## Constraints

**Zero third-party runtime dependencies.** `go list -deps ./cmd/strava-auth-proxy` must contain only
the standard library. `golang.org/x/oauth2` is permitted solely as a test dependency of
`internal/integration`; `internal/integration/deps_test.go` enforces this.

**Open question in the contract.** Bad credentials on the token endpoints return `400` — verified
live against real Strava, byte-identical to the `invalid_client_id` golden. What is *not* settled is
whether a valid `client_id` with a wrong `client_secret` reports `"field":"client_secret"` (what
this proxy currently does) or just `"field":"client_id"`. Settling it needs a real Strava app id;
the one-command check and the change to make are in `README.md`. `fakestrava` mirrors the current
choice, so the test suite cannot detect this drift on its own.
