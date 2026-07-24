# strava-auth-proxy

A single Go binary, stdlib-only, that impersonates Strava's OAuth surface. Callers
authenticate with **virtual client credentials** that you issue; the proxy substitutes
the **real** Strava application credentials on the upstream leg and reverse-proxies
everything under `/api/v3/*` verbatim.

It exists so that several apps can share one Strava application without any of them
holding the real client secret, and without any of them needing code changes: point an
existing Strava client at the proxy's base URL and it keeps working.

## The design in one paragraph

Each caller gets a **virtual** `client_id` / `client_secret` pair and an exact-match
`redirect_uri` allowlist. The proxy validates those two things — and nothing else — then
redirects the browser to real Strava with the real `client_id` and its own
`/oauth/callback` as the redirect URI (the proxy's domain is what you register as the
Authorization Callback Domain on the real Strava app). Everything the flow needs to
survive that round trip rides in an **HMAC-sealed envelope**: the `state` sent to Strava
seals `{virtual client_id, original redirect_uri, caller's own state}`, and the `code`
handed back to the caller seals `{virtual client_id, Strava's raw code}`. Both are
`kid.base64url(flate(json)).base64url(HMAC-SHA256)` with a domain-separation prefix, so
a state token can never verify as a code token. At the token endpoint the proxy checks
the virtual credentials with a constant-time compare, unseals the code, requires the
sealed `client_id` to match the presenting client, substitutes the real credentials, and
relays Strava's response **byte-for-byte**. The result is **completely stateless**: no
database, no session store, no token cache. Access and refresh tokens are Strava's own
and pass through untouched — never stored, never logged, never rewritten.

## Quick start

### 1. Generate a state key

Keys are HMAC-SHA256 keys, at least 32 bytes, hex or base64 encoded, named by a `kid`
(`[A-Za-z0-9_-]+` — no dots, the seal format uses `.` as its separator).

```sh
printf 'k1=%s\n' "$(openssl rand -hex 32)"
# k1=3f9c1e...  (64 hex chars)
```

### 2. Write the client registry

Copy `clients.example.json` to `clients.json` and edit it:

```json
[
  {
    "client_id": "90001",
    "client_secret_sha256": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    "redirect_uris": ["https://gpxapp.example/strava/cb", "http://localhost:3000/cb"]
  },
  {
    "client_id": "90002",
    "client_secret": "plain-ok-for-dev-only",
    "redirect_uris": ["https://dash.example/oauth/return"],
    "require_nonce_cookie": true
  }
]
```

Generate a secret and its digest for a new virtual client:

```sh
SECRET="$(openssl rand -hex 32)"
echo "secret (give to the caller): $SECRET"
echo "client_secret_sha256:        $(printf '%s' "$SECRET" | sha256sum | cut -d' ' -f1)"
```

Registry rules, enforced fail-fast at startup and on every reload:

- `client_id` must be an **all-digit numeric string** (`"90001"`). Strava's docs type it
  as an integer and real client libraries parse it as `int`, so a non-numeric id breaks
  the drop-in swap. Pick a range disjoint from your real Strava app id.
- No duplicate `client_id`s; every client needs at least one redirect URI.
- Exactly **one** of `client_secret_sha256` or `client_secret` per client. Plaintext is a
  dev convenience and is hashed at load.
- `redirect_uris` must be `https`, absolute, and fragment-free — except hosts
  `localhost`, `127.0.0.1` and `::1`, which may be `http` (mirroring Strava's own
  loopback whitelist).

### 3. Run it

```sh
export STRAVA_CLIENT_ID=12345
export STRAVA_CLIENT_SECRET_FILE=/run/secrets/strava_secret
export PROXY_PUBLIC_URL=https://proxy.example
export PROXY_STATE_KEYS='k1=3f9c1e...'
export PROXY_CLIENTS_FILE=/etc/proxy/clients.json
export TLS_CERT_FILE=/etc/proxy/tls.crt
export TLS_KEY_FILE=/etc/proxy/tls.key

go build -o strava-auth-proxy ./cmd/strava-auth-proxy
./strava-auth-proxy
```

For local development behind a TLS-terminating ingress, or on `localhost`, replace the
two TLS variables with `DEV_ALLOW_HTTP=true`. The proxy **refuses to bind a plain-HTTP
public listener** otherwise, at two independent gates.

Finally, on the real Strava application, set the **Authorization Callback Domain** to the
proxy's host (`proxy.example`). That is what makes the interposed callback possible.

## Configuration reference

Every variable marked *(±`_FILE`)* also honours a `<NAME>_FILE` sibling naming a file
that holds the value; the `_FILE` form wins and the contents are whitespace-trimmed.

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `STRAVA_CLIENT_ID` | yes | — | The **real** Strava application id. Never leaves the proxy except on the upstream leg. |
| `STRAVA_CLIENT_SECRET` *(±`_FILE`)* | yes | — | The **real** Strava application secret. Held as a redacting `Secret` type. |
| `PROXY_PUBLIC_URL` *(±`_FILE`)* | yes | — | Public base URL, no trailing slash (e.g. `https://proxy.example`). Builds the `/oauth/callback` redirect URI sent to Strava. |
| `PROXY_STATE_KEYS` *(±`_FILE`)* | yes | — | HMAC key ring, **newest first**: `kid=key,kid=key`. Hex or base64, ≥ 32 bytes each, unique kids matching `[A-Za-z0-9_-]+`. |
| `PROXY_CLIENTS_FILE` | yes¹ | — | Path to the virtual client registry JSON. **Primary** source. |
| `PROXY_CLIENTS` | yes¹ | — | Registry JSON inline. Fallback, used only when `PROXY_CLIENTS_FILE` is unset. |
| `PROXY_STATE_TTL` | no | `15m` | Lifetime of sealed state and sealed codes. Any `time.ParseDuration` value. |
| `LISTEN_ADDR` | no | `:8443` | Public listener address. |
| `ADMIN_ADDR` | no | `127.0.0.1:9090` | Admin listener address. Must never be exposed to callers. |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | yes² | — | TLS material for the public listener (`MinVersion` TLS 1.2). |
| `DEV_ALLOW_HTTP` | no | `false` | Development opt-in permitting a plain-HTTP public listener. |
| `UPSTREAM_BASE_URL` | no | `https://www.strava.com` | Upstream base. A test/staging injection point — the upstream host is **never** derived from request input. |
| `LOG_LEVEL` | no | `info` | `debug`, `info`, `warn` or `error`. An unparsable value degrades to `info` rather than refusing to boot. |

¹ Exactly one of `PROXY_CLIENTS_FILE` / `PROXY_CLIENTS` must be set, and the registry
must contain at least one client.
² Required unless `DEV_ALLOW_HTTP=true`.

### Endpoints

Public listener:

| Route | Behaviour |
|---|---|
| `GET /oauth/authorize`, `GET /oauth/mobile/authorize` | Validate virtual `client_id` + exact `redirect_uri`, seal state, 302 to Strava with the real `client_id`. |
| `GET /oauth/callback` | Verify sealed state, re-validate against *current* config, wrap the code, 302 to the caller. |
| `POST /oauth/token`, `POST /api/v3/oauth/token` | Both grant types on both routes. Timing-safe virtual credential check, code unwrap, real credentials substituted, response relayed verbatim. |
| `POST /oauth/deauthorize` | Pure pass-through (authenticates by `access_token`, no client credentials involved). |
| `POST /oauth/revoke` | Virtual Basic credentials validated (401 on failure), real Basic credentials re-issued upstream. |
| `/api/v3/*` | `httputil.ReverseProxy`. `Authorization` untouched, `X-Forwarded-*`/`Forwarded` stripped, gzip and rate-limit headers preserved, streamed with immediate flush. |

Admin listener: `GET /healthz`, `GET /readyz` (deliberately does **not** probe Strava — a
Strava outage must produce clean 502s, not evict every replica), `GET /metrics` (expvar
JSON: `oauth_callbacks_total`, `token_exchanges_total`, `upstream_errors_total`).

## Pointing an existing app at the proxy

It is a URL swap plus a credential swap. Nothing else changes — the proxy speaks Strava's
wire protocol, including its exact error bodies.

| Was | Becomes |
|---|---|
| `https://www.strava.com/oauth/authorize` | `https://proxy.example/oauth/authorize` |
| `https://www.strava.com/oauth/mobile/authorize` | `https://proxy.example/oauth/mobile/authorize` |
| `https://www.strava.com/api/v3/oauth/token` | `https://proxy.example/api/v3/oauth/token` |
| `https://www.strava.com/oauth/token` | `https://proxy.example/oauth/token` |
| `https://www.strava.com/oauth/deauthorize` | `https://proxy.example/oauth/deauthorize` |
| `https://www.strava.com/oauth/revoke` | `https://proxy.example/oauth/revoke` |
| `https://www.strava.com/api/v3/...` | `https://proxy.example/api/v3/...` |
| real `client_id` / `client_secret` | **virtual** `client_id` / `client_secret` |

With `golang.org/x/oauth2` that is:

```go
cfg := &oauth2.Config{
    ClientID:     "90001",              // virtual
    ClientSecret: virtualSecret,        // virtual
    RedirectURL:  "https://gpxapp.example/strava/cb",
    Scopes:       []string{"read,activity:read_all"},
    Endpoint: oauth2.Endpoint{
        AuthURL:  "https://proxy.example/oauth/authorize",
        TokenURL: "https://proxy.example/api/v3/oauth/token",
    },
}
```

The app's own `redirect_uri` stays its own — register it in `clients.json`, not on Strava.
Its own `state` round-trips bit-exact, so existing CSRF checks keep working unchanged.

## Key-rotation runbook

State keys sign envelopes that are in flight for up to `PROXY_STATE_TTL`. Rotation is
therefore a three-step process, and **each step is a `SIGHUP`, not a restart**.

1. **Prepend the new key.** Put the new kid *first* — the ring signs with `[0]` and
   verifies against every entry.
   ```sh
   PROXY_STATE_KEYS='k2=<new 64-hex>,k1=<old 64-hex>'
   kill -HUP "$(pidof strava-auth-proxy)"
   ```
   New envelopes are signed with `k2`; envelopes already out in browsers still verify
   under `k1`.
2. **Wait longer than `PROXY_STATE_TTL`** (default 15 minutes; use 20 to be safe). After
   that no `k1`-signed envelope can still be valid.
3. **Drop the old key.**
   ```sh
   PROXY_STATE_KEYS='k2=<new 64-hex>'
   kill -HUP "$(pidof strava-auth-proxy)"
   ```

Never reuse a retired kid with new key material: a same-kid foreign key fails the MAC and
is indistinguishable from a forgery in the logs.

`SIGHUP` re-reads and fully validates the configuration and swaps it in **only on
success** — an invalid registry is logged and discarded while the previous configuration
stays live. Adding or removing a virtual client is therefore zero-downtime. Mid-flight
authorizations are safe by construction: `/oauth/callback` re-validates the sealed
`redirect_uri` against the *current* config, so a client removed mid-flow gets a 400 page
rather than a redirect.

## Operational caveats

These are inherent to the shared-real-app model, not defects. Read them before onboarding
a second tenant.

- **Deauthorize/revoke fans out across virtual clients.** Revoking one athlete's token
  revokes *the real application's* grant for that athlete — which affects **every**
  virtual client that athlete has authorized. A user who disconnects from app A is
  disconnected from apps B and C too. This cannot be fixed at the proxy; it is how
  Strava scopes grants. Tell your tenants.
- **Rate limits are shared.** All virtual clients draw on one real application's quota
  (15-minute and daily, overall and read-only). `X-RateLimit-*` / `X-ReadRateLimit-*`
  headers pass through verbatim but are **not** partitioned per virtual client, so one
  noisy tenant can 429 everyone. Partitioning would require per-client state, which was
  rejected for minimalism.
- **Tokens are not bound to a virtual client.** Access and refresh tokens are Strava's
  own and pass through untouched, so a token issued through client A's flow works when
  presented by client B. Binding them would mean rewriting token responses (breaking
  verbatim relay) and re-wrapping on rotation. **Virtual clients are mutually trusting
  tenants of a single operator** — do not use this proxy as a boundary between parties
  that distrust each other.
- Related, smaller ones: authorization codes remain single-use (Strava enforces it, the
  proxy does not retry an ambiguous token exchange because a retry would burn the code);
  there is no per-client scope policy (`scope` is forwarded verbatim); `redirect_uri`
  matching is **exact**, deliberately stricter than Strava's domain-level matching; and
  the caller's `state` is capped at 1 KB so oversized values fail loudly at the proxy
  instead of mysteriously at Strava.

## Security posture

- Sealed envelopes are authenticated, **not** encrypted. Their contents are non-secret by
  construction: a client id, a redirect URI, the caller's own state, and a Strava code
  that is unusable without the real secret (which only the proxy holds).
- Verification order is kid lookup → `hmac.Equal` → decompress/parse → `iat` window. No
  attacker-controlled bytes are interpreted before the MAC passes.
- Virtual secrets are stored as SHA-256 digests and compared with
  `subtle.ConstantTimeCompare`. The Fault body deliberately discloses `client_id` vs
  `client_secret` for Strava fidelity, so no claim is made that unknown-id is
  indistinguishable from wrong-secret; the constant-time compare prevents byte-position
  secret recovery, nothing more.
- Every `/oauth/*` response carries `Referrer-Policy: no-referrer` and
  `Cache-Control: no-store`. Access logs record the route pattern, path, status and
  virtual client id — **never** a query string (logged as `?<redacted>`), header, cookie
  or body.
- The real secret only ever appears in outbound requests to `UPSTREAM_BASE_URL`. It is
  held in a `config.Secret` whose `String`, `GoString`, `Format`, `MarshalJSON` and
  `LogValue` all yield `[REDACTED]`, so `slog.Info("cfg", "config", cfg)` is structurally
  incapable of leaking it.
- The upstream host comes from configuration only, never from request input — non-SSRF by
  construction. There is **no** `InsecureSkipVerify` code path anywhere, not even
  flag-gated; a test greps the source to keep it that way.
- Inbound `X-Forwarded-*` / `Forwarded` are stripped and `SetXForwarded` is never called:
  caller topology is neither leaked to Strava nor spoofable by callers.

## Development

```sh
go build ./...
go vet ./...
go test ./...
go test -race -count=1 ./...
go test -run Fuzz -fuzz FuzzOpen -fuzztime 30s ./internal/seal/
```

Zero third-party **runtime** dependencies — `go list -deps ./cmd/strava-auth-proxy`
contains only the standard library. `golang.org/x/oauth2` appears in `go.mod` solely as a
test dependency of `internal/integration`, which uses it to prove the drop-in swap works
against a real client library.

The authoritative design document is [`docs/DESIGN.md`](docs/DESIGN.md); the verified
Strava wire contract is [`docs/STRAVA-CONTRACT.md`](docs/STRAVA-CONTRACT.md).

> **Note on error status codes — verified 2026-07-24.** Bad credentials on the token
> endpoints return **`400`**, not the `401` that one documentation source claimed. This was
> checked against real Strava with deliberately invalid values; the response is byte-identical
> to the proxy's `invalid_client_id` golden. Details of every probe are in
> [`docs/STRAVA-CONTRACT.md`](docs/STRAVA-CONTRACT.md). No change was needed.
>
> One sub-case remains open, and it needs a **real** Strava application id to settle: whether
> a *valid* `client_id` with a *wrong* `client_secret` reports `"field":"client_secret"` or
> just `"field":"client_id"`. Every probe with an unknown id returned `client_id`, even when
> `client_secret` was omitted entirely, which suggests Strava's error may be generic. Check it
> with your own app id (the secret below is deliberately wrong, so nothing is exposed):
>
> ```sh
> curl -sS -X POST https://www.strava.com/oauth/token \
>   -d "client_id=<your real app id>&client_secret=deliberately-wrong&grant_type=refresh_token&refresh_token=x"
> ```
>
> If it reports `client_id`, drop `WriteInvalidClientSecret` from
> `internal/fault/fault.go` and have `internal/oauth/token.go` return the `client_id` fault
> for both failure modes. That would also be a small security win: the proxy would stop
> acting as an oracle for which virtual `client_id`s exist, and the constant-time secret
> comparison would no longer be undercut by a response body that names the failing field.
