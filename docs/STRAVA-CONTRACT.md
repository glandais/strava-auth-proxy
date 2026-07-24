# Strava API Authentication Contract Reference

Source: https://developers.strava.com/docs/authentication/ plus the official Swagger spec (developers.strava.com/swagger/*) and rate-limit docs. Verified 2026-07-24.

## Base URLs

| Purpose | Base |
|---|---|
| Browser-facing OAuth pages (authorize, mobile authorize) | `https://www.strava.com/oauth/*` |
| Token exchange (documented) | `https://www.strava.com/api/v3/oauth/token` |
| Token refresh (documented) | `https://www.strava.com/oauth/token` |
| Deauthorize / revoke | `https://www.strava.com/oauth/deauthorize`, `https://www.strava.com/oauth/revoke` |
| All other API calls | `https://www.strava.com/api/v3/*` (host `www.strava.com`, basePath `/api/v3`, HTTPS only) |

Note: the docs show token exchange under `/api/v3/oauth/token` and refresh under `/oauth/token`; in practice both paths accept both grant types — replicate both routes.

---

## 1. Authorization — `GET https://www.strava.com/oauth/authorize`

Browser redirect endpoint (renders Strava's consent page).

| Parameter | Type | Required | Allowed values / notes |
|---|---|---|---|
| `client_id` | integer | required | Application ID from app registration |
| `redirect_uri` | string | required | Must match the app's registered Authorization Callback Domain; `localhost` and `127.0.0.1` are always whitelisted |
| `response_type` | string | required | Must be `code` |
| `scope` | string | required | Comma- or space-delimited list of scopes (see below) |
| `approval_prompt` | string | optional | `auto` (default) or `force` (`force` re-shows the consent screen even if already authorized) |
| `state` | string | optional | Opaque value, echoed back unchanged in the redirect |

### Scope values
- `read` — public segments, routes, profiles, posts, events, club feeds, leaderboards
- `read_all` — read private routes, private segments, private events
- `profile:read_all` — all profile info regardless of visibility settings
- `profile:write` — update weight and FTP; star/unstar segments
- `activity:read` — activities visible to Everyone/Followers, excluding privacy-zone data
- `activity:read_all` — `activity:read` plus privacy-zone data and "Only You" activities
- `activity:write` — create/upload activities; update title, type, description, visibility of visible activities

The user may grant a **subset** of requested scopes on the consent screen; apps must handle partial grants.

### Redirect callback (to `redirect_uri`, query string)
- Success: `code=<authorization code>&scope=<granted scopes>&state=<state if sent>`
  - `code` is short-lived and single-use.
  - `scope` contains the scopes **actually granted** (may differ from requested). Values are comma-delimited in the callback (e.g. `scope=read,activity:read_all`).
- Denial: `error=access_denied` (plus `state` if sent). No `code` is present.

---

## 2. Mobile Authorization — `GET https://www.strava.com/oauth/mobile/authorize`

Identical parameters, semantics, and callback behavior to `/oauth/authorize`; intended for mobile apps (works with the Strava app / app links so the user can authorize via the installed app instead of a web login). Same success/denial redirect contract.

---

## 3. Token Exchange — `POST https://www.strava.com/api/v3/oauth/token`

Exchanges the authorization `code` for tokens. Parameters are sent as form fields (query params also accepted).

| Parameter | Type | Required | Value |
|---|---|---|---|
| `client_id` | integer | required | |
| `client_secret` | string | required | |
| `code` | string | required | Code from the redirect callback |
| `grant_type` | string | required | Must be `authorization_code` |

### 200 response body
```json
{
  "token_type": "Bearer",
  "expires_at": 1568775134,
  "expires_in": 21600,
  "refresh_token": "e5n567567...",
  "access_token": "a4b945687g...",
  "athlete": { /* SummaryAthlete, see below */ }
}
```

| Field | Type | Notes |
|---|---|---|
| `token_type` | string | Always `"Bearer"` |
| `expires_at` | integer (epoch seconds) | When the access token expires |
| `expires_in` | integer (seconds) | Seconds until expiry (access tokens live 6 hours = 21600 s) |
| `refresh_token` | string | Long-lived; store it |
| `access_token` | string | Short-lived (6 h) |
| `athlete` | object | Summary representation of the authenticated athlete — **present only on `authorization_code` exchange, not on refresh** |

### SummaryAthlete object (`athlete` field)
| Field | Type | Notes |
|---|---|---|
| `id` | integer (int64) | Unique athlete identifier |
| `resource_state` | integer | 1 = meta, 2 = summary, 3 = detail (2 here) |
| `firstname` | string | |
| `lastname` | string | |
| `profile_medium` | string | URL, 62x62 px picture |
| `profile` | string | URL, 124x124 px picture |
| `city` | string | |
| `state` | string | |
| `country` | string | |
| `sex` | string | `M` or `F` |
| `premium` | boolean | Deprecated (use `summit`) |
| `summit` | boolean | Has a Summit/subscription |
| `created_at` | string (date-time) | |
| `updated_at` | string (date-time) | |

(Live responses also commonly include `username`, `badge_type_id`, `friend`, `follower` — nullable/extra fields; the fields above are the contractual Swagger set.)

---

## 4. Token Refresh — `POST https://www.strava.com/oauth/token`

| Parameter | Type | Required | Value |
|---|---|---|---|
| `client_id` | integer | required | |
| `client_secret` | string | required | |
| `grant_type` | string | required | Must be `refresh_token` |
| `refresh_token` | string | required | Most recent refresh token for the user |

Behavior: if the current access token expires in **more than one hour**, the same access token is returned; if it expires in **≤ 3600 s**, a new access token is issued. The response may contain a **new `refresh_token`** — always persist the returned one. Old access tokens are invalidated when a new one is issued.

### 200 response body (no `athlete` field)
```json
{
  "token_type": "Bearer",
  "access_token": "a9b723...",
  "expires_at": 1568775134,
  "expires_in": 20566,
  "refresh_token": "b5c569..."
}
```

---

## 5. Deauthorization

### Legacy — `POST https://www.strava.com/oauth/deauthorize` (deprecated; sunset after June 1, 2027)
| Parameter | Type | Required |
|---|---|---|
| `access_token` | string | required (also accepted as `Authorization: Bearer` header) |

Revokes the application's access for that athlete (invalidates all tokens for the app/athlete pair). 200 response body echoes the token: `{"access_token": "..."}`. Invalid token → 401 Fault.

### Current (recommended as of June 1, 2026) — `POST https://www.strava.com/oauth/revoke`
- Auth: HTTP Basic — `Authorization: Basic base64(client_id:client_secret)`
- Parameters:

| Parameter | Type | Required | Values |
|---|---|---|---|
| `token` | string | required | The token to revoke |
| `token_type_hint` | string | optional | `access_token` or `refresh_token` |

- Success: **HTTP 200, empty body** (returns 200 even for unknown tokens, per RFC 7009 semantics)
- Errors: `400 Bad Request` (missing `token`), `401 Unauthorized` (bad Basic credentials), `503 Service Unavailable`

---

## 6. Using tokens on API calls

Header: `Authorization: Bearer <access_token>` on all `https://www.strava.com/api/v3/*` requests. Access tokens expire six hours after creation.

---

## 7. Error contract (Fault model)

All API/OAuth errors use the Fault shape:
```json
{
  "message": "string",
  "errors": [
    { "resource": "string", "field": "string", "code": "string" }
  ]
}
```

Known auth-specific instances (observed/canonical behavior):

| Situation | Status | Body |
|---|---|---|
| Unknown `client_id` on token endpoints | **400** (verified, see below) | `{"message":"Bad Request","errors":[{"resource":"Application","field":"client_id","code":"invalid"}]}` |
| Known `client_id`, wrong `client_secret` | **401** (verified, see below) | `{"message":"Authorization Error","errors":[{"resource":"Application","field":"","code":"invalid"}]}` |
| Invalid/expired/reused authorization `code` | 400 | `{"message":"Bad Request","errors":[{"resource":"AuthorizationCode","field":"code","code":"invalid"}]}` |
| Invalid/revoked refresh token | 400 | `{"message":"Bad Request","errors":[{"resource":"RefreshToken","field":"refresh_token","code":"invalid"}]}` |
| Missing/expired/invalid access token on API call | 401 | `{"message":"Authorization Error","errors":[{"resource":"Athlete","field":"access_token","code":"invalid"}]}` |
| Missing required scope | 401/403 | Fault with `"resource":"AccessToken"`-style error |
| Rate limit exceeded | 429 | `{"message":"Rate Limit Exceeded","errors":[{"resource":"Application","field":"rate limit","code":"exceeded"}]}` |

General status codes: 200 OK, 201 Created, 401 Unauthorized, 403 Forbidden, 404 Not Found, 429 Too Many Requests, 500 Server Error.

### Live verification of the token-endpoint credential error (2026-07-24)

Probed against real Strava with deliberately invalid values (no real credentials needed).
Every one of the following returned **`400`** with a byte-identical body:

```
{"message":"Bad Request","errors":[{"resource":"Application","field":"client_id","code":"invalid"}]}
```

| Probe | Endpoint |
|---|---|
| unknown `client_id` + bogus `client_secret`, `grant_type=authorization_code` | `/api/v3/oauth/token` and `/oauth/token` |
| unknown `client_id` + bogus `client_secret`, `grant_type=refresh_token` | `/oauth/token` |
| `client_secret` omitted entirely | `/oauth/token` |
| `grant_type` omitted / unknown `grant_type` | `/oauth/token` |
| empty request body | `/oauth/token` |

Every one of those probes used an `client_id` that does not exist.

### Settled with a real application id (2026-07-24)

Re-probed with a **real** Strava application id and a deliberately wrong secret. This
overturns the reading above: both documentation sources were right, about different cases.
The token endpoints are **asymmetric**.

| Case | Status | Body |
|---|---|---|
| **Unknown** `client_id` | `400` | `{"message":"Bad Request","errors":[{"resource":"Application","field":"client_id","code":"invalid"}]}` |
| **Known** `client_id`, wrong `client_secret` | `401` | `{"message":"Authorization Error","errors":[{"resource":"Application","field":"","code":"invalid"}]}` |

Note the empty `field` on the 401 — Strava names the failing field only when the
application is unknown. Both shapes were observed identically on `/oauth/token` and
`/api/v3/oauth/token`, for both `authorization_code` and `refresh_token` grants.

`POST /oauth/revoke` behaves differently again: bad HTTP Basic credentials return `401`
with an **empty errors array**, `{"message":"Authorization Error","errors":[]}`, for both an
unknown `client_id` and a wrong secret. Revoke is therefore not an oracle for which
applications exist, while the token endpoints are.

Consequences for the proxy, all now implemented:

- `fault.WriteInvalidClientID` → `400`, unchanged.
- `fault.WriteInvalidClientSecret` → `401` `"Authorization Error"` with an empty `field`.
- `fault.WriteUnauthorized` (revoke) → `401` with an empty errors array.
- `internal/fakestrava` reproduces all three, so the integration suite exercises the real
  shapes rather than a convenient fiction.

The status-code split matters for drop-in fidelity: a client library that treats `401` as
"re-authenticate" and `400` as "fatal configuration error" would take a different branch
under the old behaviour.

By contrast, `POST /oauth/deauthorize` and `/api/v3/*` with a bogus bearer token return
`401` with `{"message":"Authorization Error","errors":[{"resource":"Athlete","field":"access_token","code":"invalid"}]}`
— a third shape, and one the proxy passes straight through.

---

## 8. Rate-limit headers (on every `/api/v3/*` response)

| Header | Format | Meaning |
|---|---|---|
| `X-RateLimit-Limit` | `int,int` | Overall limits: per-15-minute, per-day (e.g. `600,30000`) |
| `X-RateLimit-Usage` | `int,int` | Overall usage: per-15-minute, per-day (e.g. `314,27536`) |
| `X-ReadRateLimit-Limit` | `int,int` | Read-only request limits: 15-min, daily |
| `X-ReadRateLimit-Usage` | `int,int` | Read-only usage: 15-min, daily |

Defaults for new apps: overall 200 req/15 min and 2,000/day; read 100 req/15 min and 1,000/day. 15-minute windows reset at :00/:15/:30/:45; daily at midnight UTC. Exceeding limits → HTTP 429 with the Fault body above. (Docs render header casing inconsistently — `X-Ratelimit-Usage` in examples vs `X-RateLimit-Usage` in definitions; treat headers case-insensitively.)

---

### Implementation gotchas for exact replication
- `scope` in the **redirect callback is comma-delimited**; `scope` requested may be comma- or space-delimited; token-exchange responses have historically omitted a `scope` field (granted scopes come from the callback) — do not rely on it.
- `athlete` appears **only** in the `authorization_code` grant response.
- Refresh may return the same access token (if >1 h validity remains) and may rotate the refresh token.
- `expires_at` is absolute epoch seconds; `expires_in` is relative seconds; both always present.
- Denial redirect carries `error=access_denied` and no `code`.
