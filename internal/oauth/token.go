package oauth

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/glandais/strava-auth-proxy/internal/fault"
	"github.com/glandais/strava-auth-proxy/internal/httpmid"
	"github.com/glandais/strava-auth-proxy/internal/metrics"
	"github.com/glandais/strava-auth-proxy/internal/seal"
)

// Grant types the proxy recognises. Recognition changes exactly one thing —
// whether the wrapped code is unwrapped — and never gates the request: an
// unknown grant_type is forwarded so Strava mints its own canonical error.
const (
	grantAuthorizationCode = "authorization_code"
	grantRefreshToken      = "refresh_token"
)

// Form parameters the token handler owns; every other parameter, known or not,
// is forwarded verbatim.
var tokenOwnedParams = map[string]bool{
	"client_id":     true,
	"client_secret": true,
}

// Outcome labels recorded on metrics.TokenExchanges, alongside the upstream
// status labels produced by statusOutcome.
const (
	outcomeMalformedRequest = "malformed_request"
	outcomeBadClientID      = "invalid_client_id"
	outcomeBadClientSecret  = "invalid_client_secret"
	outcomeBadCode          = "invalid_code"
)

// Token serves POST /oauth/token and POST /api/v3/oauth/token.
//
// Both routes accept both grant types, mirroring Strava, whose documentation
// splits them across the two paths while the live service accepts either on
// either. Parameters are read from the form body or the query string, again
// because Strava accepts both.
//
// The virtual credentials are verified here and replaced by the real Strava
// application credentials on the upstream leg. Exactly one upstream attempt is
// made: authorization codes are single-use, so retrying an ambiguous failure
// would burn the code and turn a transient error into a permanent one.
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	cfg := h.Cfg.Get()

	if err := r.ParseForm(); err != nil {
		metrics.Inc(metrics.TokenExchanges, key("", outcomeMalformedRequest))
		fault.WriteInvalidClientID(w)
		return
	}
	grant := r.Form.Get("grant_type")

	client, ok := cfg.Client(r.Form.Get("client_id"))
	if !ok {
		metrics.Inc(metrics.TokenExchanges, key(grant, outcomeBadClientID))
		fault.WriteInvalidClientID(w)
		return
	}
	httpmid.SetClientID(r, client.ID)
	if !client.VerifySecret(r.Form.Get("client_secret")) {
		metrics.Inc(metrics.TokenExchanges, key(grant, outcomeBadClientSecret))
		fault.WriteInvalidClientSecret(w)
		return
	}

	out := make(url.Values, len(r.Form)+2)
	for k, vs := range r.Form {
		if tokenOwnedParams[k] {
			continue
		}
		out[k] = append([]string(nil), vs...)
	}

	if grant == grantAuthorizationCode {
		var cp seal.CodePayload
		wrapped := r.Form.Get("code")
		if err := h.ring(cfg).Open(seal.DomainCode, wrapped, &cp, cfg.StateTTL, h.now()); err != nil {
			metrics.Inc(metrics.TokenExchanges, key(grant, outcomeBadCode))
			h.logger().Warn("rejecting wrapped code", "client_id", client.ID, "error", err)
			fault.WriteInvalidCode(w)
			return
		}
		// The code is bound to the client whose flow minted it. Without this
		// check, a code leaked from client A's redirect could be exchanged by
		// client B using its own valid credentials.
		if cp.CID != client.ID {
			metrics.Inc(metrics.TokenExchanges, key(grant, outcomeBadCode))
			h.logger().Warn("wrapped code presented by a different client", "client_id", client.ID)
			fault.WriteInvalidCode(w)
			return
		}
		out.Set("code", cp.SC)
	}

	// Real credentials are substituted only after the virtual ones have been
	// verified, so an unauthenticated caller can never make the proxy spend the
	// real application's identity upstream.
	out.Set("client_id", cfg.StravaClientID)
	out.Set("client_secret", cfg.StravaClientSecret.Reveal())

	target, err := upstreamURL(cfg, pathToken)
	if err != nil {
		h.logger().Error("building upstream token URL failed", "error", err)
		metrics.Inc(metrics.TokenExchanges, key(grant, outcomeInternal))
		fault.WriteUpstreamUnavailable(w)
		return
	}

	body := out.Encode()
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target.String(), strings.NewReader(body))
	if err != nil {
		h.logger().Error("building upstream token request failed", "error", err)
		metrics.Inc(metrics.TokenExchanges, key(grant, outcomeInternal))
		fault.WriteUpstreamUnavailable(w)
		return
	}
	req.Header.Set("Content-Type", contentTypeForm)
	req.Header.Set("Accept", "application/json")
	req.ContentLength = int64(len(body))

	// One attempt, no retry. The response — tokens, the athlete object,
	// undocumented fields and all — is relayed byte-for-byte and never parsed.
	status := h.relay(w, req, "token")
	if status == 0 {
		metrics.Inc(metrics.TokenExchanges, key(grant, outcomeUpstreamError))
		return
	}
	metrics.Inc(metrics.TokenExchanges, key(grant, statusOutcome(status)))
}

// statusOutcome labels a relayed upstream status.
func statusOutcome(status int) string {
	if status >= 200 && status < 300 {
		return outcomeSuccess
	}
	return outcomeUpstreamError
}

// key builds a metrics key of the form "grant_type:outcome".
//
// grant_type is caller-controlled, so it is folded to a small fixed set before
// becoming a map key: an expvar map grows without bound, and a caller that can
// mint keys can grow the process's memory at will.
func key(grant, outcome string) string {
	switch grant {
	case grantAuthorizationCode, grantRefreshToken:
	case "":
		grant = "none"
	default:
		grant = "other"
	}
	return grant + ":" + outcome
}
