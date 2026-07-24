package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"

	"github.com/glandais/strava-auth-proxy/internal/config"
	"github.com/glandais/strava-auth-proxy/internal/fault"
	"github.com/glandais/strava-auth-proxy/internal/httpmid"
	"github.com/glandais/strava-auth-proxy/internal/seal"
)

// MaxCallerStateLen caps the caller's own state parameter.
//
// The sealed envelope carries that state to Strava inside a URL, so an
// unbounded state would fail deep inside Strava's stack with an opaque error.
// The seal payload is flate-compressed before signing, which typically buys
// 2-3x headroom, so this cap is the loud, early backstop rather than the
// primary line of defense.
const MaxCallerStateLen = 1024

// NonceCookieName is the opt-in double-submit cookie set for virtual clients
// configured with require_nonce_cookie.
//
// The __Host- prefix is not decoration: it forces the browser to reject the
// cookie unless it is Secure, host-scoped (no Domain attribute) and set with
// Path=/, which removes the sibling-subdomain injection that plain cookie
// double-submit is vulnerable to.
const NonceCookieName = "__Host-sap_nonce"

// nonceLen is the number of random bytes behind a nonce cookie value.
const nonceLen = 32

// Query parameters the authorize handler owns; every other caller parameter is
// forwarded to Strava untouched.
var authorizeOwnedParams = map[string]bool{
	"client_id":    true,
	"redirect_uri": true,
	"state":        true,
}

// Authorize serves GET /oauth/authorize.
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	h.authorize(w, r, pathAuthorize)
}

// MobileAuthorize serves GET /oauth/mobile/authorize. It is identical to
// [Handler.Authorize] except for the upstream path.
func (h *Handler) MobileAuthorize(w http.ResponseWriter, r *http.Request) {
	h.authorize(w, r, pathMobileAuthorize)
}

// authorize validates the two parameters the proxy must gate — the virtual
// client_id and the redirect_uri — then redirects the browser to Strava with
// the real client_id, the proxy's own callback URI and a sealed state.
//
// Every failure renders a 400 page. It never redirects on error: at this point
// the redirect target has either not been validated or has been rejected, and
// redirecting to it would turn the proxy into an open redirector (OAuth 2.0
// §4.1.2.1).
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request, upstreamPath string) {
	cfg := h.Cfg.Get()
	q := r.URL.Query()

	clientID, _ := firstParam(q, "client_id")
	client, ok := cfg.Client(clientID)
	if !ok {
		fault.WriteBadRequestPage(w, "Unknown client_id.")
		return
	}
	httpmid.SetClientID(r, client.ID)

	redirectURI, _ := firstParam(q, "redirect_uri")
	if !client.AllowsRedirectURI(redirectURI) {
		// Exact-match only, deliberately stricter than Strava's domain-level
		// matching: the proxy is the open-redirect chokepoint.
		fault.WriteBadRequestPage(w, "The redirect_uri is not registered for this client.")
		return
	}

	callerState, hasState := firstParam(q, "state")
	if len(callerState) > MaxCallerStateLen {
		fault.WriteBadRequestPage(w, "The state parameter is too long.")
		return
	}

	payload := seal.StatePayload{
		CID:   client.ID,
		RU:    redirectURI,
		ST:    callerState,
		HasST: hasState,
		IAT:   h.now().Unix(),
	}

	if client.RequireNonceCookie {
		nonce, err := newNonce()
		if err != nil {
			h.logger().Error("generating nonce failed", "error", err)
			writeInternal(w)
			return
		}
		payload.Nonce = nonce
		http.SetCookie(w, nonceCookie(nonce, cfg))
	}

	sealed, err := h.ring(cfg).Seal(seal.DomainState, payload)
	if err != nil {
		h.logger().Error("sealing state failed", "error", err)
		writeInternal(w)
		return
	}

	target, err := upstreamURL(cfg, upstreamPath)
	if err != nil {
		h.logger().Error("building upstream authorize URL failed", "error", err)
		writeInternal(w)
		return
	}

	// Everything the proxy does not own — scope, response_type,
	// approval_prompt and any parameter Strava may add tomorrow — is forwarded
	// verbatim so Strava renders its own canonical errors.
	out := make(url.Values, len(q)+3)
	for k, vs := range q {
		if authorizeOwnedParams[k] {
			continue
		}
		out[k] = append([]string(nil), vs...)
	}
	out.Set("client_id", cfg.StravaClientID)
	out.Set("redirect_uri", cfg.CallbackURL())
	out.Set("state", sealed)
	target.RawQuery = out.Encode()

	http.Redirect(w, r, target.String(), http.StatusFound)
}

// newNonce returns a fresh, URL-safe 256-bit random value.
func newNonce() (string, error) {
	b := make([]byte, nonceLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// nonceCookie builds the double-submit cookie. Its lifetime tracks the state
// TTL: the cookie is worthless once the state it is bound to has expired.
func nonceCookie(value string, cfg *config.Config) *http.Cookie {
	return &http.Cookie{
		Name:     NonceCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(cfg.StateTTL.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// clearNonceCookie expires the double-submit cookie. The attributes must match
// the ones it was set with, or the browser keeps the original cookie.
func clearNonceCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     NonceCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
