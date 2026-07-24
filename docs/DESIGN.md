# strava-auth-proxy — Final Design Document

A single Go binary, stdlib-only, that impersonates Strava's OAuth surface for callers holding **virtual client credentials**, substitutes the **real** Strava application credentials on the upstream leg, and transparently reverse-proxies everything else under `/api/v3/*`. Stateless with respect to tokens: no database, no token cache — all flow context lives in HMAC-sealed, self-authenticating envelopes.

---

## 1. Architecture overview

```
                 ┌─────────────────────────── proxy (single binary) ───────────────────────────┐
 caller app ──►  │  mux:                                                                        │
 (holds only     │   GET  /oauth/authorize          ─┐ validate virtual client_id +             │
  VIRTUAL creds) │   GET  /oauth/mobile/authorize   ─┘ redirect_uri, 302 → Strava with REAL     │
                 │                                     client_id + sealed state                 │
                 │   GET  /oauth/callback             verify state, wrap code, 302 → app        │
                 │   POST /oauth/token              ─┐ validate virtual creds (timing-safe),    │
                 │   POST /api/v3/oauth/token       ─┘ unwrap code, substitute REAL creds,      │──► https://www.strava.com
                 │                                     relay Strava response verbatim           │
                 │   POST /oauth/deauthorize          pure pass-through (auth = access_token)   │
                 │   POST /oauth/revoke               validate virtual Basic creds, substitute  │
                 │   *    /api/v3/*                   httputil.ReverseProxy, Bearer untouched   │
                 ├──────────────────────────────────────────────────────────────────────────────┤
                 │  admin listener (separate port): /healthz  /readyz  /metrics (expvar)        │
                 └──────────────────────────────────────────────────────────────────────────────┘
```

**Components**

- `oauth` handlers — the four OAuth surfaces plus the interposed `/oauth/callback`.
- `seal` — one generic HMAC envelope mechanism (`Seal`/`Open`) with a **kid-based key ring** and **domain-separation prefixes**, used for both the packed state and the wrapped code.
- `upstream` — the `/api/v3/*` reverse proxy and the outbound `http.Client` used by the token/revoke handlers (shared hardened `Transport`).
- `config` — file-first configuration with env fallback, redacting secret types, validate-before-swap SIGHUP hot reload via `atomic.Pointer[Config]`.
- `fault` — Strava Fault-shaped error writers, golden-tested byte-for-byte.

**Statelessness invariant.** The proxy holds no per-user or per-session storage. Flow context rides in two sealed tokens:

- **Packed state** (the `state` param sent to Strava): `kid.base64url(payload).base64url(HMAC-SHA256)` over payload `{cid, ru, st, iat}` — virtual client_id, original redirect_uri, caller's original state, issued-at.
- **Wrapped code** (what the caller receives as `code`): same envelope over `{cid, sc, iat}` — virtual client_id, Strava's raw code, issued-at. The caller treats it as an opaque authorization code, which is all OAuth requires.

Access/refresh tokens are Strava's own, passed through byte-for-byte, never persisted, never inspected beyond form parsing on the token endpoint.

**Design invariants (stated, not accidental)**

1. **No retries, no circuit breaker** on proxy→Strava calls. Authorization codes are single-use: retrying a token exchange after an ambiguous failure burns the code; a circuit breaker converts a Strava brownout into a full local outage. One attempt; the caller sees Strava's error or a proxy 502/504 Fault and decides.
2. **Non-SSRF / non-open-proxy by construction**: the upstream host is a fixed constant (`https://www.strava.com`), never derived from any request input.
3. **Tokens flow through verbatim**: no rewriting, wrapping, or logging of access/refresh tokens.
4. **Only what the proxy needs is validated at the proxy**: `client_id` and `redirect_uri` gate the redirect and must be checked locally; everything else (`scope`, `response_type`, `approval_prompt`, unknown params) is forwarded verbatim so Strava produces its own canonical errors — every local validation is a potential contract-divergence point.

### 1.1 The full authorize → callback → token sequence

Actors: **Browser** (resource owner), **App** (virtual client `90001` / secret, callback `https://app.example/cb`), **Proxy** (`https://proxy.example`, holds real Strava creds `RID`/`RSECRET`), **Strava**.

1. **App → Browser → Proxy**
   `GET https://proxy.example/oauth/authorize?client_id=90001&redirect_uri=https://app.example/cb&response_type=code&scope=read,activity:read_all&state=abc&approval_prompt=auto`
2. **Proxy validates only what it must**: `90001` exists in the registry; `redirect_uri` is an **exact match** against that client's allowlist. On failure: 400 error page (with `Cache-Control: no-store`, `Referrer-Policy: no-referrer`), **never** a redirect to an unvalidated URI. All other params — including missing `scope` or `response_type != code` — are forwarded so Strava renders its own error UX. Proxy seals state `P` over `{cid:"90001", ru:"https://app.example/cb", st:"abc", iat:now}` with domain prefix `sapstate.v1`.
3. **Proxy → Browser**: `302 Location: https://www.strava.com/oauth/authorize?client_id=RID&redirect_uri=https://proxy.example/oauth/callback&response_type=code&scope=read,activity:read_all&approval_prompt=auto&state=P` (mobile variant redirects to `/oauth/mobile/authorize`; everything else identical).
4. **Browser ↔ Strava**: user logs in, sees the consent page, possibly grants a subset of scopes, approves or denies.
5. **Strava → Browser → Proxy**: `302 → https://proxy.example/oauth/callback?code=C&scope=read,activity:read_all&state=P` — possible because `proxy.example` is the **Authorization Callback Domain registered on the real Strava app**. Denial arrives as `error=access_denied&state=P` (or any other `error` value Strava may emit).
6. **Proxy `/oauth/callback`** (response always carries `Referrer-Policy: no-referrer` and `Cache-Control: no-store`): verifies `P` (kid lookup → HMAC verify → parse payload; TTL default 15 min; reject `iat` more than 60 s in the future), re-looks-up `cid` and **re-validates `ru` against current config** (config may have been hot-reloaded mid-flight). Then:
   - **success**: seals wrapped code `W` over `{cid:"90001", sc:C, iat:now}` with prefix `sapcode.v1`; `302 Location: https://app.example/cb?code=W&scope=read,activity:read_all&state=abc` — granted `scope` (comma-delimited, exactly as Strava sent it) and the caller's original `state` round-trip untouched.
   - **denial/error**: forwards **whatever `error` value Strava sent, verbatim**: `302 Location: https://app.example/cb?error=<as-received>&state=abc`. No hardcoded `access_denied`.
   - **bad/missing/expired/tampered `P`**: 400 error page, no redirect.
7. **App backend → Proxy**: `POST /oauth/token` (or `/api/v3/oauth/token`; both routes accept both grant types, as Strava's do) with form fields `client_id=90001&client_secret=…&code=W&grant_type=authorization_code`.
8. **Proxy**: timing-safe-validates virtual credentials; opens `W` (kid → MAC → parse; TTL; **`cid` must equal the presenting client** — a code minted in client A's flow is unusable by client B); POSTs to `https://www.strava.com/api/v3/oauth/token` with `client_id=RID&client_secret=RSECRET&code=C&grant_type=authorization_code`; relays Strava's status + JSON body **verbatim** (so `athlete`, including undocumented fields like `username`, survives intact). One attempt, no retry.
9. **Refresh (any time later)**: `POST /oauth/token` with `grant_type=refresh_token&refresh_token=R&client_id=90001&client_secret=…`. Proxy validates virtual creds, substitutes real creds, forwards all other params verbatim, relays the response byte-for-byte (no `athlete`; possibly rotated `refresh_token` — Strava's doing, untouched).

---

## 2. Endpoint-by-endpoint contract

All `/oauth/*` responses (redirects, error pages, JSON) carry `Referrer-Policy: no-referrer` and `Cache-Control: no-store` — raw and wrapped codes transit URLs and must never leak via referrer or caches. This is set by a middleware wrapping every `/oauth/*` route and asserted in tests.

### 2.1 `GET /oauth/authorize` and `GET /oauth/mobile/authorize`

**In (query):**

| Param | Proxy behavior |
|---|---|
| `client_id` | **Validated**: must exist in virtual registry (numeric string, e.g. `90001`) |
| `redirect_uri` | **Validated**: exact-match against that client's allowlist |
| `response_type`, `scope`, `approval_prompt` | Forwarded verbatim — Strava enforces its own rules and error UX |
| `state` | Optional; ≤ 1 KB (see 2.1 errors); embedded in packed state, round-trips bit-exact |

**Out:** `302` to the corresponding Strava path (`/oauth/authorize` or `/oauth/mobile/authorize`) with real `client_id`, `redirect_uri=<PROXY_PUBLIC_URL>/oauth/callback`, sealed `state`, and all other caller params passed through.

**Errors** (400 `text/html` page, never a redirect — OAuth 2.0 §4.1.2.1 posture for invalid client/redirect_uri):
- unknown `client_id`; missing or non-allowlisted `redirect_uri`;
- `state` exceeding 1 KB after sealing overhead (would breach practical URL limits at Strava). Mitigation reserve: the seal payload is `flate`-compressed before signing, which typically buys 2–3× headroom before the cap bites; the cap is the loud, early backstop, not the primary line.

### 2.2 `GET /oauth/callback` (proxy-internal; the URI registered on the real Strava app)

**In (query, from Strava):** `code`+`scope`+`state`, or `error=<value>`+`state`.

**Out:**
- success: `302 → <ru>?code=<wrapped>&scope=<verbatim>&state=<original state, omitted if the caller sent none>`
- error: `302 → <ru>?error=<verbatim>&state=<original>` — **any** error value forwarded unchanged.
- invalid/expired/tampered `state`, or `ru` no longer allowlisted under current config: 400 page, no redirect.

**Opt-in hardening (per-client flag `require_nonce_cookie: true`, default off):** for virtual clients that don't use their own `state`, the authorize handler sets a `__Host-sap_nonce` cookie (Secure, HttpOnly, SameSite=Lax, Path=/) whose value is bound into the sealed state; the callback requires the double-submit match before redirecting. Strictly opt-in — default-on would break cookie-hostile webviews and violate drop-in fidelity.

### 2.3 `POST /oauth/token` and `POST /api/v3/oauth/token`

Params accepted as `application/x-www-form-urlencoded` body **or** query string (Strava accepts both).

- `grant_type=authorization_code`: `client_id`, `client_secret` (virtual), `code` (wrapped), `grant_type`. Proxy → Strava `/api/v3/oauth/token` with real creds + unwrapped code. 200 body relayed verbatim: `{token_type:"Bearer", expires_at, expires_in, refresh_token, access_token, athlete:{…}}`.
- `grant_type=refresh_token`: `client_id`, `client_secret`, `grant_type`, `refresh_token`. Forwarded with creds substituted; 200 body verbatim (no `athlete`).
- Any other params: forwarded verbatim.

**Errors** — exact Fault shapes; proxy-minted for virtual-cred failures, relayed byte-for-byte when Strava produces them:

| Case | Origin | Status / body |
|---|---|---|
| bad virtual `client_id` | proxy | **`400`** `{"message":"Bad Request","errors":[{"resource":"Application","field":"client_id","code":"invalid"}]}` |
| bad virtual `client_secret` (client exists) | proxy | **`401`** `{"message":"Authorization Error","errors":[{"resource":"Application","field":"","code":"invalid"}]}` — verified live; see the note below |
| malformed/expired/foreign-client wrapped code | proxy | `400` `{"message":"Bad Request","errors":[{"resource":"AuthorizationCode","field":"code","code":"invalid"}]}` |
| Strava rejects code / refresh token | Strava, relayed | Strava's own Fault, status + body verbatim |
| unknown/missing `grant_type` | Strava, relayed | forwarded upstream (with real creds substituted only after virtual creds validate); Strava's canonical error returned — no proxy-minted grant_type fault |
| Strava unreachable | proxy | `502` `{"message":"Bad Gateway","errors":[{"resource":"Upstream","field":"strava","code":"unavailable"}]}` |
| Strava timeout | proxy | `504` `{"message":"Gateway Timeout","errors":[{"resource":"Upstream","field":"strava","code":"timeout"}]}` |

> **Resolved 2026-07-24 against live Strava** (this supersedes the design's original working assumption of a symmetric 400). The token endpoints are asymmetric: an **unknown** `client_id` is `400 "Bad Request"` naming the field, a **known** `client_id` with a wrong secret is `401 "Authorization Error"` with an empty `field`. `/oauth/revoke` is `401` with an empty errors array for both. All three shapes are implemented, golden-tested, and mirrored in `internal/fakestrava`; the probe log is in `docs/STRAVA-CONTRACT.md`. The consequence for §2.3's timing note below is that the disclosure it accepts is now known to be real Strava's behaviour rather than an assumption.

**Timing posture (coherent, no theater):** stored virtual secrets are SHA-256 pre-hashed; the presented secret is hashed and compared with `crypto/subtle.ConstantTimeCompare` (equal-length inputs by construction). The Fault body deliberately discloses `client_id` vs `client_secret` for Strava fidelity, so we make **no claim** that unknown-id is indistinguishable from wrong-secret — the constant-time compare exists to prevent byte-position secret recovery, not to hide which field failed.

### 2.4 `POST /oauth/deauthorize`

Legacy endpoint authenticates by `access_token` (form param or `Authorization: Bearer`) — no client credentials involved — so it is a **pure pass-through** to `https://www.strava.com/oauth/deauthorize`. Response (200 `{"access_token":"…"}` or 401 Fault) relayed verbatim.

### 2.5 `POST /oauth/revoke`

`Authorization: Basic base64(virtual_id:virtual_secret)` validated timing-safely (bad Basic creds → `401`, matching Strava's documented revoke behavior), then re-issued upstream with `Basic base64(RID:RSECRET)`; `token` / `token_type_hint` form fields forwarded untouched. 200-empty / 400 / 503 relayed verbatim.

### 2.6 `/api/v3/*` catch-all reverse proxy

`httputil.ReverseProxy` with a `Rewrite` hook:

- `r.Out.URL.Scheme = "https"`, `r.Out.URL.Host = "www.strava.com"`, `r.Out.Host = "www.strava.com"` (fixes the `Host` header).
- **Strip inbound `X-Forwarded-For` / `X-Forwarded-Host` / `X-Forwarded-Proto` / `Forwarded` and do not call `SetXForwarded`** — caller topology is neither leaked to Strava nor spoofable by callers.
- `Authorization` header untouched — never read, logged, or stored.
- Transport: `DisableCompression: true` with the client's own `Accept-Encoding` forwarded, so gzip bodies pass through compressed and `Content-Encoding`/`Content-Length` remain correct.
- Streaming both directions; `FlushInterval: -1` (immediate flush) — matters for large activity streams and uploads.
- All response headers pass through automatically (only hop-by-hop stripped per RFC 7230), including `X-RateLimit-*` / `X-ReadRateLimit-*` in any casing; 429/401/403 Fault bodies byte-for-byte.
- `ErrorHandler`: `502` Fault `code:"unavailable"` on connect failure, `504` `code:"timeout"` on context deadline; client disconnects propagate via request context (upstream call is cancelled, nothing logged as an error).
- `POST /api/v3/oauth/token` is registered as an exact path on the mux and therefore wins over the catch-all (`net/http.ServeMux` most-specific-pattern matching).

### 2.7 Admin listener (separate port, e.g. `:9090`)

- `GET /healthz` — process liveness, always 200 once serving.
- `GET /readyz` — readiness; **deliberately does not probe Strava**. A Strava outage should yield clean 502s to callers, not self-eviction from the load balancer.
- `GET /metrics` — `expvar` (stdlib) counters: `oauth_callbacks_total{outcome}`, `token_exchanges_total{grant_type,outcome}`, `upstream_errors_total{kind}`, rendered as expvar JSON. No Prometheus dependency; a scraper-friendly text endpoint can be hand-rolled later if needed.

---

## 3. Go project layout

Zero third-party runtime dependencies (`go.mod` has no `require` lines; `golang.org/x/oauth2` appears only as a **test** dependency for the drop-in proof test). Whole binary ~1000–1200 LOC, auditable in one sitting, `FROM scratch`-friendly static build.

```
strava-auth-proxy/
├── go.mod
├── cmd/strava-auth-proxy/
│   └── main.go            # load+validate config, wire mux + admin mux, http.Server
│                          #   (ReadHeaderTimeout set; NO WriteTimeout so long /api/v3
│                          #   streams survive), TLS/dev-flag enforcement, SIGHUP
│                          #   hot-reload loop, graceful shutdown
└── internal/
    ├── config/
    │   ├── config.go      # file-first load (clients file primary, env JSON fallback),
    │   │                  #   *_FILE indirection, startup validation (numeric client_ids,
    │   │                  #   no duplicates, https-only redirect_uris except
    │   │                  #   localhost/127.0.0.1/[::1], key length ≥ 32 bytes,
    │   │                  #   plaintext dev secrets hashed at load), atomic.Pointer[Config]
    │   │                  #   holder with Validate-then-Swap reload
    │   └── secret.go      # type Secret: String()/GoString()/Format()/MarshalJSON()/
    │                      #   LogValue() all return "[REDACTED]"; structurally impossible
    │                      #   to leak via fmt or slog
    ├── seal/seal.go       # generic envelope: Seal(domain, payload, key ring) /
    │                      #   Open(domain, token, key ring, ttl, maxSkew).
    │                      #   Format: kid "." b64url(flate(JSON)) "." b64url(mac)
    │                      #   MAC input: domain-prefix || payload  ("sapstate.v1" /
    │                      #   "sapcode.v1" — cryptographic type separation).
    │                      #   Open order: kid lookup → hmac.Equal → decompress/parse →
    │                      #   iat window check. One fuzz target.
    ├── fault/fault.go     # Fault struct + canned writers (WriteInvalidClientID,
    │                      #   WriteInvalidCode, WriteUpstreamUnavailable, ...) — the
    │                      #   single source of every proxy-minted error body
    ├── httpmid/mid.go     # /oauth/* header middleware (Referrer-Policy, Cache-Control),
    │                      #   access logging: route PATTERN only, query string logged as
    │                      #   "?<redacted>" on all /oauth/* routes, never tokens/secrets;
    │                      #   fields: method, pattern, virtual client_id, status, latency
    ├── oauth/
    │   ├── authorize.go   # /oauth/authorize + /oauth/mobile/authorize
    │   ├── callback.go    # /oauth/callback (incl. verbatim error forwarding,
    │   │                  #   optional __Host- nonce double-submit)
    │   ├── token.go       # /oauth/token + /api/v3/oauth/token, both grant types,
    │   │                  #   timing-safe cred check, cid-bound code unwrap, verbatim relay
    │   └── revoke.go      # /oauth/deauthorize pass-through + /oauth/revoke Basic swap
    └── upstream/
        ├── transport.go   # shared *http.Transport: MinVersion TLS1.2, no
        │                  #   InsecureSkipVerify field anywhere in the codebase,
        │                  #   DisableCompression, sane dial/TLS timeouts; base URL
        │                  #   injectable for tests
        └── proxy.go       # ReverseProxy: Rewrite hook (host set, X-Forwarded-*/
                           #   Forwarded stripped, no SetXForwarded), FlushInterval -1,
                           #   ErrorHandler 502/504 Faults
```

**Libraries:** `net/http`, `net/http/httputil`, `net/url`, `crypto/hmac`, `crypto/sha256`, `crypto/subtle`, `crypto/tls`, `compress/flate`, `encoding/base64`, `encoding/json`, `expvar`, `log/slog`, `os`, `os/signal`, `sync/atomic`, `time`, `context`. Justification for zero deps: every need is first-class in the stdlib; supply-chain surface is nil.

**TLS posture (explicit):**
- The public listener refuses to bind plain HTTP unless `DEV_ALLOW_HTTP=true` is set (intended for `localhost` behind a TLS-terminating ingress or local dev only); with TLS enabled, `MinVersion: tls.VersionTLS12`.
- Upstream `Transport` sets `MinVersion: tls.VersionTLS12`; there is **no** `InsecureSkipVerify` code path — not even flag-gated.

---

## 4. Configuration

File-first for the multi-client registry (an env-var JSON registry is an operational foot-gun for the exact multi-tenant case the proxy exists for); env vars for scalars and secrets, with `*_FILE` indirection for orchestrator secret mounts.

```sh
# Real Strava application (never leaves the proxy)
STRAVA_CLIENT_ID=12345
STRAVA_CLIENT_SECRET_FILE=/run/secrets/strava_secret   # or STRAVA_CLIENT_SECRET=...

# Proxy identity
PROXY_PUBLIC_URL=https://proxy.example      # builds the /oauth/callback redirect_uri
LISTEN_ADDR=:8443
ADMIN_ADDR=127.0.0.1:9090
TLS_CERT_FILE=/etc/proxy/tls.crt
TLS_KEY_FILE=/etc/proxy/tls.key
# DEV_ALLOW_HTTP=true                       # dev only; refused otherwise

# HMAC key ring: newest first; sign with [0], verify against all.
# Each entry: kid=hex-or-base64-key, >= 32 bytes. Rotation: prepend a new kid,
# keep the old one listed for >= PROXY_STATE_TTL, then drop it.
PROXY_STATE_KEYS='k2=9f3c...64hex,k1=77aa...64hex'      # or PROXY_STATE_KEYS_FILE=...
PROXY_STATE_TTL=15m                                      # optional, default 15m

# Virtual client registry — file is primary, PROXY_CLIENTS env JSON is the fallback
PROXY_CLIENTS_FILE=/etc/proxy/clients.json
```

`/etc/proxy/clients.json`:

```json
[
  {
    "client_id": "90001",
    "client_secret_sha256": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    "redirect_uris": ["https://gpxapp.example/strava/cb", "http://localhost:3000/cb"]
  },
  {
    "client_id": "90002",
    "client_secret": "plain-ok-for-dev",
    "redirect_uris": ["https://dash.example/oauth/return"],
    "require_nonce_cookie": true
  }
]
```

**Rules, enforced fail-fast at startup and on every reload:**

- `client_id` values must be **all-digit numeric strings** (`"90001"`). Rationale: Strava's docs type `client_id` as an integer and real client libraries (including Strava-branded SDKs) parse it as `int` — a non-numeric id breaks the drop-in URL swap at the caller's config time, not at runtime. Pick a range disjoint from your real Strava app id.
- No duplicate `client_id`s; every client has ≥ 1 redirect URI.
- `redirect_uris` must be `https` except hosts `localhost`, `127.0.0.1`, `[::1]` (mirrors Strava's own localhost whitelist).
- Secrets: SHA-256 hex preferred; plaintext accepted and hashed at load (dev convenience — no pre-hashing tooling required).
- Every state key ≥ 32 bytes; ring non-empty.
- All secret-bearing fields deserialize into `config.Secret` — `String`, `GoString`, `Format`, `MarshalJSON`, and `LogValue` all yield `[REDACTED]`, so `slog.Info("cfg", "config", cfg)` is structurally incapable of leaking the real Strava secret.

**Hot reload:** `SIGHUP` triggers re-read → full validation → `atomic.Pointer[Config].Store` only on success; on failure the old config stays live and the error is logged. Adding a virtual client is a zero-downtime operation. Mid-flight authorizations are safe by construction because `/oauth/callback` re-validates `redirect_uri` against the *current* config.

---

## 5. Security analysis of the redirect/state/code mechanism

**Why an interposed callback is mandatory.** Strava only redirects to the real app's registered Authorization Callback Domain. Virtual clients' redirect URIs live on arbitrary domains, so the proxy must register `proxy.example` as that domain and re-redirect. There is no stateless alternative.

**Envelope construction.** `kid || "." || base64url(flate(canonical JSON)) || "." || base64url(HMAC-SHA256(key[kid], domain-prefix || payload-bytes))`.

- **Key ring (kid-based):** sign with the newest key (`keys[0]`), verify against every listed key. Rotation is prepend-new / retire-old-after-TTL — in-flight authorizations survive rotation, and a MAC failure is unambiguously a forgery or expiry, never "wrong key epoch".
- **Domain separation:** the MAC input is prefixed with `"sapstate.v1"` or `"sapcode.v1"`. A state token can never verify as a code token (or vice versa) *cryptographically* — type confusion is rejected before any payload parsing, not by a parse-then-check field.
- **Verification order discipline:** kid lookup → `hmac.Equal` → decompress/parse → `iat` window check (expired beyond TTL, or future-dated beyond 60 s clock skew → reject). No attacker-controlled bytes are parsed before the MAC passes.

**Threat-by-threat:**

- **Integrity / CSRF on the Strava leg:** the callback only acts on a MAC-valid `state`; an attacker cannot fabricate or mutate the (virtual client, redirect target, caller state) tuple. The caller's own CSRF defense is its `state`, round-tripped bit-exact — existing client-side checks work unchanged. For state-less callers, the opt-in `__Host-` nonce double-submit cookie adds binding without breaking webview-based callers (which is why it is never default-on).
- **Open redirect:** the callback redirects only to the `ru` inside a MAC-valid state, which was exact-match allowlisted at mint time **and is re-checked against current config at callback time**. Exact match, not prefix or domain match — stricter than Strava, deliberately, because the proxy is the open-redirect chokepoint. Every failure path renders a page instead of redirecting.
- **Code leak / confused deputy:** the raw Strava code transits Strava→proxy→(wrapped)→app. Decoding a wrapped code reveals the raw code, but it is unusable: Strava demands the real secret (proxy-only), and the proxy only exchanges MAC-valid wrapped codes whose embedded `cid` equals the presenting virtual client — client A cannot exchange a code phished from client B's flow. `Referrer-Policy: no-referrer` and `Cache-Control: no-store` on every `/oauth/*` response, plus query-string redaction in logs, close the URL-leak side channels.
- **Replay:** statelessness precludes proxy-side single-use enforcement, but Strava enforces single-use on the underlying code — a replayed wrapped code fails upstream with the canonical `AuthorizationCode invalid` Fault. State replay within TTL only restarts a redirect to an allowlisted URI. 15-minute TTLs bound both windows.
- **Confidentiality:** envelope payloads are readable (compressed base64, not encrypted). Nothing in them is secret: a redirect URI, a client id, the caller's own state, and a Strava code unusable without the real secret. AES-GCM sealing is a ~20-line stdlib upgrade if opacity is ever wanted; HMAC-only keeps flows debuggable.
- **Credential checking:** SHA-256 pre-hash + `subtle.ConstantTimeCompare`. Field-level disclosure in Fault bodies is a Strava-fidelity requirement and is accepted; see §2.3 for the honest statement of what the constant-time compare does and does not provide.
- **Forwarding metadata:** inbound `X-Forwarded-*`/`Forwarded` stripped, `SetXForwarded` never called — Strava sees the proxy as the client; callers cannot spoof origin metadata.
- **Residual trust assumption:** access/refresh tokens are not virtual-client-bound (see trade-off 1). Virtual clients are mutually trusting tenants of one operator.

---

## 6. Testing strategy

**Step-0 live verification (one-time, manual):** hit real Strava's `/oauth/token` with deliberately bad credentials and record the exact status+body; encode that pair into the golden Fault tests. Status-code drift (400 vs 401) sends drop-in client libraries down different error paths — the observed behavior, not documentation, is the contract.

**Unit tests**

- `seal`: round-trip; single-bit tamper of payload and MAC → reject; expired and future-dated `iat` → reject; unknown kid → reject; **cross-domain confusion** (state opened as code and vice versa) → reject; sign-with-new/verify-with-old rotation scenario; one fuzz target over `Open`.
- `config`: file-vs-env precedence, `*_FILE` indirection, plaintext-vs-hash secrets, and fail-fast rows for: non-numeric client_id, duplicate ids, non-https redirect_uri (with localhost/127.0.0.1/[::1] exceptions passing), short key, empty ring, malformed JSON. Reload: invalid new config keeps old config live.
- `config.Secret`: `fmt.Sprintf("%v/%s/%#v")`, `json.Marshal`, and `slog` output all yield `[REDACTED]`.
- `oauth`: table-driven `httptest.NewRecorder` tests — every proxy-minted error row asserted **byte-for-byte** against golden Fault JSON; redirect `Location` parsing (params, scope verbatim, state round-trip, state omitted when caller sent none); **arbitrary `error` values forwarded verbatim** on the denial path; creds-in-query-string acceptance; exact-match redirect_uri rejections (`…/cb/evil`, `app.example.evil`); `scope`/`response_type` pass-through (no proxy 400 minted); cross-client code theft rejected; headers `Referrer-Policy`/`Cache-Control` present on every `/oauth/*` response.
- `httpmid`: **tested invariant** — a spy `slog.Handler` captures log records for `/oauth/callback?code=…&state=…` and `/oauth/token?client_secret=…` requests and the test asserts no query-string content appears anywhere in any record (pattern + `?<redacted>` only).

**Integration: `fakestrava` (httptest.Server)** implementing `GET /oauth/authorize` (immediate 302 with minted code + configurable granted-scope subset, or configurable `error` values), `POST /api/v3/oauth/token` + `/oauth/token` (validates real creds, single-use codes, athlete-on-exchange-only, refresh-rotation toggle), `/oauth/deauthorize`, `/oauth/revoke`, and an `/api/v3/*` echo handler emitting rate-limit headers, gzip bodies, and a chunked streamed response. The proxy's upstream base URL is injectable. Scenarios driven with `http.Client{CheckRedirect: …}` through the entire dance: authorize → fake Strava → callback → final app redirect → exchange → verbatim token JSON → refresh → revoke. Plus: expired/tampered state, config-hot-reload-mid-flow (client removed → callback 400s; client kept → flow completes), gzip passthrough (body still compressed), rate-limit header fidelity (mixed casing), Bearer-header byte-equality (fake records received headers), `X-Forwarded-*` absence at the fake, 502/504 Fault shapes when the fake is down/hanging, and no-retry assertion (fake counts exactly one token attempt after an injected failure).

**Drop-in proof test:** configure `golang.org/x/oauth2` (test-only dependency) with `Endpoint{AuthURL: proxy + "/oauth/authorize", TokenURL: proxy + "/oauth/token"}` and a virtual credential; run the full flow against proxy+fakestrava and assert the transcript is param-for-param what the library produces against Strava directly. Alongside it, a **secret-leak sweep**: a spy slog handler plus capture of every proxy response body/header across all integration scenarios, regex-swept for the real Strava secret — zero matches required.

**Optional live smoke test** behind a build tag, run manually against real Strava with a sandbox app.

---

## 7. Open questions / conscious trade-offs

1. **Refresh/access tokens are not virtual-client-bound.** Binding would require wrapping tokens in responses (breaking verbatim relay and needing re-wrap on rotation). Chosen: pure pass-through; virtual clients are mutually trusting tenants of one operator. Wrappable later behind a flag using the same `seal` package.
2. **Deauthorize/revoke fan-out:** revoking one athlete's token revokes the *real app's* grant for that athlete — affecting every virtual client that athlete used. Inherent to the shared-real-app model; not fixable at the proxy.
3. **Shared rate limits:** all virtual clients consume one real app's quota; headers pass through but are not partitioned. A per-client limiter adds state — rejected for minimalism.
4. **Caller `state` cap (1 KB)** with flate compression as the working reserve: oversized states fail loudly at the proxy rather than mysteriously at Strava. A slight deviation from "anything goes," surfaced early.
5. **No scope policy per virtual client** (passed verbatim). A per-client `allowed_scopes` field is an easy future config addition.
6. **Exact-match redirect URIs** vs Strava's domain-level matching: stricter, deliberately (see §5). Multiple URIs per client cover legitimate variance.
7. **`/oauth/authorize` proxy-side errors render pages, not redirects** — but the proxy now only errors for the two things it must gate (client_id, redirect_uri); all other malformed-request UX is Strava's own, eliminating contract divergence.
8. **HMAC, not encryption**, for envelopes: contents are non-secret by construction; transparency aids debugging and audit.
9. **`/oauth/revoke` uses 401 for bad Basic creds** (Strava documents 401 there) while the token endpoints use the observed 400 Fault — an intentional asymmetry mirroring Strava's own.
10. **Metrics via expvar, not Prometheus**, to hold the zero-dependency line; revisit only if operators demand a scrape format.
11. **`response_type` values other than `code`** are forwarded, meaning Strava's error page (not the proxy's) handles them — correct for fidelity, but it means the proxy never sees a token grant attempt to refuse locally. Accepted.

---

## 8. Ordered implementation plan

1. **Live-contract verification (step 0):** with a real Strava sandbox app, capture exact status+body for (a) bad `client_id`/`client_secret` on `/oauth/token`, (b) bad/reused code, (c) bad refresh token, (d) denial redirect params. Commit these as golden fixtures under `internal/fault/testdata/` and `internal/oauth/testdata/`.
2. `internal/config`: types (`Secret` redacting wrapper first), file/env loading, `*_FILE` indirection, full startup validation (numeric ids, dup check, https rule, key sizes), `atomic.Pointer[Config]` holder. Unit tests including the redaction tests.
3. `internal/seal`: key ring, domain prefixes, flate compression, `Seal`/`Open` with verification-order discipline. Unit tests + fuzz target.
4. `internal/fault`: Fault struct + writers matching the step-1 fixtures byte-for-byte. Golden tests.
5. `internal/httpmid`: `/oauth/*` header middleware + redacting access logger. Spy-handler log tests.
6. `internal/upstream`: hardened shared `Transport` (TLS 1.2 min, injectable base URL), then the ReverseProxy (`Rewrite` with header stripping, `FlushInterval: -1`, 502/504 `ErrorHandler`).
7. `internal/oauth/authorize.go` + `callback.go`: the redirect dance, verbatim error forwarding, opt-in nonce cookie. Handler unit tests.
8. `internal/oauth/token.go` + `revoke.go`: timing-safe validation, code unwrap with cid binding, verbatim relay, no-retry single-attempt calls. Handler unit tests against golden fixtures.
9. `cmd/strava-auth-proxy/main.go`: mux wiring (exact-path token routes before the `/api/v3/` catch-all), TLS/dev-flag enforcement, `ReadHeaderTimeout` (no `WriteTimeout`), admin listener (`/healthz`, `/readyz`, expvar `/metrics`), SIGHUP reload loop, graceful shutdown.
10. `internal/fakestrava` + full integration suite (§6), including the hot-reload-mid-flow, gzip, rate-limit, and no-retry scenarios.
11. Drop-in proof test with `golang.org/x/oauth2` (test-only dep) + the secret-leak regex sweep.
12. Optional build-tagged live smoke test; README with config reference, key-rotation runbook (prepend kid, wait ≥ TTL, drop old), and the deauthorize fan-out caveat for tenants.
