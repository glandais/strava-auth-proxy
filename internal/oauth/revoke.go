package oauth

import (
	"encoding/base64"
	"net/http"

	"github.com/glandais/strava-auth-proxy/internal/config"
	"github.com/glandais/strava-auth-proxy/internal/fault"
	"github.com/glandais/strava-auth-proxy/internal/httpmid"
)

// passthroughHeaders are the request headers forwarded on the pass-through
// legs. The list is an allowlist rather than a copy of everything: forwarding
// hop-by-hop headers, cookies or caller-supplied forwarding metadata to Strava
// would leak topology or corrupt the connection.
var passthroughHeaders = []string{"Content-Type", "Accept", "Accept-Language", "User-Agent"}

// Deauthorize serves POST /oauth/deauthorize, Strava's legacy deauthorization
// endpoint.
//
// It authenticates with the athlete's access_token — as a form field or a
// Bearer header — and involves no client credentials at all, so there is
// nothing for the proxy to validate or substitute: this is a pure
// pass-through. The body is streamed rather than parsed, so the access token is
// never held, inspected or logged.
func (h *Handler) Deauthorize(w http.ResponseWriter, r *http.Request) {
	cfg := h.Cfg.Get()

	target, err := upstreamURL(cfg, pathDeauthorize)
	if err != nil {
		h.logger().Error("building upstream deauthorize URL failed", "error", err)
		fault.WriteUpstreamUnavailable(w)
		return
	}
	target.RawQuery = r.URL.RawQuery

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target.String(), r.Body)
	if err != nil {
		h.logger().Error("building upstream deauthorize request failed", "error", err)
		fault.WriteUpstreamUnavailable(w)
		return
	}
	req.ContentLength = r.ContentLength
	copyRequestHeaders(req, r)
	// The Bearer credential, when used, belongs to the athlete and is passed
	// through untouched.
	if v := r.Header.Get("Authorization"); v != "" {
		req.Header.Set("Authorization", v)
	}

	h.relay(w, req, "deauthorize")
}

// Revoke serves POST /oauth/revoke, the current (RFC 7009-shaped) revocation
// endpoint.
//
// Authentication is HTTP Basic with the *virtual* client credentials, verified
// timing-safely; the upstream leg is re-issued with the real application's
// credentials. The token and token_type_hint fields are forwarded untouched,
// and the response — 200 with an empty body, 400, 401 or 503 — is relayed
// verbatim.
//
// Bad credentials answer 401, not the 400 the token endpoints use. The
// asymmetry is Strava's, and the proxy mirrors it rather than normalising it.
func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	cfg := h.Cfg.Get()

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		fault.WriteUnauthorized(w)
		return
	}
	client, found := cfg.Client(clientID)
	if !found {
		// Compare against a zero digest anyway: this endpoint answers with a
		// single 401 for both failure modes, so unlike the token endpoints it
		// costs nothing to keep the two paths' work comparable.
		(&config.Client{}).VerifySecret(clientSecret)
		fault.WriteUnauthorized(w)
		return
	}
	if !client.VerifySecret(clientSecret) {
		httpmid.SetClientID(r, client.ID)
		fault.WriteUnauthorized(w)
		return
	}
	httpmid.SetClientID(r, client.ID)

	target, err := upstreamURL(cfg, pathRevoke)
	if err != nil {
		h.logger().Error("building upstream revoke URL failed", "error", err)
		fault.WriteUpstreamUnavailable(w)
		return
	}
	target.RawQuery = r.URL.RawQuery

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target.String(), r.Body)
	if err != nil {
		h.logger().Error("building upstream revoke request failed", "error", err)
		fault.WriteUpstreamUnavailable(w)
		return
	}
	req.ContentLength = r.ContentLength
	copyRequestHeaders(req, r)
	req.Header.Set("Authorization", basicAuthHeader(cfg.StravaClientID, cfg.StravaClientSecret.Reveal()))

	h.relay(w, req, "revoke")
}

// copyRequestHeaders copies the allowlisted headers from the inbound request.
func copyRequestHeaders(dst *http.Request, src *http.Request) {
	for _, name := range passthroughHeaders {
		if v := src.Header.Get(name); v != "" {
			dst.Header.Set(name, v)
		}
	}
}

// basicAuthHeader renders an HTTP Basic Authorization header value.
func basicAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}
