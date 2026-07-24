package oauth

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"

	"github.com/glandais/strava-auth-proxy/internal/fault"
	"github.com/glandais/strava-auth-proxy/internal/httpmid"
	"github.com/glandais/strava-auth-proxy/internal/metrics"
	"github.com/glandais/strava-auth-proxy/internal/seal"
)

// Outcome labels recorded on metrics.OAuthCallbacks.
const (
	outcomeSuccess         = "success"
	outcomeUpstreamError   = "upstream_error"
	outcomeBadState        = "bad_state"
	outcomeExpiredState    = "expired_state"
	outcomeUnknownClient   = "unknown_client"
	outcomeRedirectRevoked = "redirect_uri_revoked"
	outcomeNonceMismatch   = "nonce_mismatch"
	outcomeMissingCode     = "missing_code"
	outcomeInternal        = "internal_error"
)

// errorPassthroughParams are forwarded, when present, alongside the error value
// Strava sent, so the caller sees the same diagnostic detail it would have seen
// talking to Strava directly.
var errorPassthroughParams = []string{"error_description", "error_uri"}

// Callback serves GET /oauth/callback — the redirect URI registered on the real
// Strava application, and the only stateful-looking step in an otherwise
// stateless proxy.
//
// The sealed state is the sole source of truth for where to redirect next. It
// is authenticated first; only then is the virtual client re-resolved and its
// redirect URI re-validated against the *current* configuration, so a client
// removed by a hot reload mid-flight cannot complete a flow. Any failure before
// that point renders a 400 page rather than redirecting, because an
// unauthenticated state names an unvalidated target.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	cfg := h.Cfg.Get()
	q := r.URL.Query()

	stateToken, _ := firstParam(q, "state")
	var st seal.StatePayload
	if err := h.ring(cfg).Open(seal.DomainState, stateToken, &st, cfg.StateTTL, h.now()); err != nil {
		outcome := outcomeBadState
		detail := "The authorization state is missing, malformed or has been tampered with."
		if errors.Is(err, seal.ErrExpired) {
			outcome = outcomeExpiredState
			detail = "The authorization request has expired. Please start again."
		}
		metrics.Inc(metrics.OAuthCallbacks, outcome)
		h.logger().Warn("rejecting callback state", "outcome", outcome, "error", err)
		fault.WriteBadRequestPage(w, detail)
		return
	}
	httpmid.SetClientID(r, st.CID)

	// Re-resolve against the live config: the registry may have been reloaded
	// while the user was on Strava's consent page.
	client, ok := cfg.Client(st.CID)
	if !ok {
		metrics.Inc(metrics.OAuthCallbacks, outcomeUnknownClient)
		fault.WriteBadRequestPage(w, "The client that started this authorization is no longer registered.")
		return
	}
	if !client.AllowsRedirectURI(st.RU) {
		metrics.Inc(metrics.OAuthCallbacks, outcomeRedirectRevoked)
		fault.WriteBadRequestPage(w, "The redirect_uri is no longer registered for this client.")
		return
	}

	if client.RequireNonceCookie {
		presented := ""
		if c, err := r.Cookie(NonceCookieName); err == nil {
			presented = c.Value
		}
		// Clear it either way: the nonce is single-use, and a stale cookie
		// would otherwise linger for the whole TTL.
		clearNonceCookie(w)
		if st.Nonce == "" || subtle.ConstantTimeCompare([]byte(presented), []byte(st.Nonce)) != 1 {
			metrics.Inc(metrics.OAuthCallbacks, outcomeNonceMismatch)
			fault.WriteBadRequestPage(w, "The authorization could not be verified. Please start again.")
			return
		}
	}

	dst, err := url.Parse(st.RU)
	if err != nil {
		// Unreachable for a URI that passed config validation at mint time and
		// again just above; handled rather than trusted.
		metrics.Inc(metrics.OAuthCallbacks, outcomeInternal)
		h.logger().Error("sealed redirect_uri does not parse", "client_id", st.CID)
		writeInternal(w)
		return
	}
	out := dst.Query()

	// Error leg: forward whatever error value Strava sent, unchanged. Nothing
	// is hardcoded to access_denied — Strava may emit values this proxy has
	// never heard of, and the caller must see them as Strava wrote them.
	if errVal, present := firstParam(q, "error"); present {
		out.Set("error", errVal)
		for _, name := range errorPassthroughParams {
			if v, ok := firstParam(q, name); ok {
				out.Set(name, v)
			}
		}
		h.finishRedirect(w, r, dst, out, st, outcomeUpstreamError)
		return
	}

	code, _ := firstParam(q, "code")
	if code == "" {
		metrics.Inc(metrics.OAuthCallbacks, outcomeMissingCode)
		fault.WriteBadRequestPage(w, "Strava returned neither an authorization code nor an error.")
		return
	}

	// Wrap Strava's raw code. The wrapper binds it to the virtual client that
	// started the flow, which is what makes a code phished from client A's
	// flow unusable by client B at the token endpoint.
	wrapped, err := h.ring(cfg).Seal(seal.DomainCode, seal.CodePayload{
		CID: st.CID,
		SC:  code,
		IAT: h.now().Unix(),
	})
	if err != nil {
		metrics.Inc(metrics.OAuthCallbacks, outcomeInternal)
		h.logger().Error("sealing code failed", "error", err)
		writeInternal(w)
		return
	}
	out.Set("code", wrapped)
	// Granted scope is Strava's word on what the user actually approved: it is
	// copied verbatim, and omitted entirely when Strava sent none.
	if scope, ok := firstParam(q, "scope"); ok {
		out.Set("scope", scope)
	}
	h.finishRedirect(w, r, dst, out, st, outcomeSuccess)
}

// finishRedirect echoes the caller's own state (only if it sent one) and
// redirects. The redirect URL is rebuilt through net/url, never by string
// concatenation, so a redirect URI that already carries a query string keeps it
// and every value is escaped exactly once.
func (h *Handler) finishRedirect(w http.ResponseWriter, r *http.Request, dst *url.URL, out url.Values, st seal.StatePayload, outcome string) {
	if st.HasST {
		out.Set("state", st.ST)
	}
	dst.RawQuery = out.Encode()
	metrics.Inc(metrics.OAuthCallbacks, outcome)
	http.Redirect(w, r, dst.String(), http.StatusFound)
}
