// Package oauth implements the proxy's OAuth surface: the two authorize
// endpoints, the interposed callback, the two token endpoints, and the
// deauthorize/revoke endpoints.
//
// The package holds no state. Everything a flow needs to survive the round trip
// through the browser rides in the HMAC envelopes minted by
// [github.com/glandais/strava-auth-proxy/internal/seal]: the packed state sent
// to Strava, and the wrapped authorization code handed back to the virtual
// client.
//
// Two rules shape every handler here:
//
//   - Validate only what the proxy must. The virtual client_id and the
//     redirect_uri gate the redirect and are checked locally; scope,
//     response_type, approval_prompt, grant_type and every unknown parameter are
//     forwarded verbatim so that Strava produces its own canonical errors. Each
//     local validation would be a contract-divergence point.
//   - Relay Strava verbatim. Upstream status codes and bodies are passed
//     through byte-for-byte; access and refresh tokens are never parsed, logged
//     or stored.
package oauth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/glandais/strava-auth-proxy/internal/config"
	"github.com/glandais/strava-auth-proxy/internal/fault"
	"github.com/glandais/strava-auth-proxy/internal/metrics"
	"github.com/glandais/strava-auth-proxy/internal/seal"
)

// Upstream paths on Strava. They are constants, never derived from request
// input, which is what makes the proxy non-SSRF by construction.
const (
	pathAuthorize       = "/oauth/authorize"
	pathMobileAuthorize = "/oauth/mobile/authorize"
	pathToken           = "/api/v3/oauth/token"
	pathDeauthorize     = "/oauth/deauthorize"
	pathRevoke          = "/oauth/revoke"
)

// contentTypeForm is the media type of every server-to-server request body the
// proxy builds itself.
const contentTypeForm = "application/x-www-form-urlencoded"

// Handler serves the proxy's OAuth endpoints. The zero value is not usable:
// Cfg and Client must be set. Ring may be left nil, in which case the key ring
// is derived from the live configuration on every request, so a SIGHUP that
// rotates keys takes effect immediately.
type Handler struct {
	// Cfg publishes the live configuration snapshot.
	Cfg *config.Holder
	// Ring overrides the HMAC key ring; nil means "use Cfg's state keys".
	Ring seal.Ring
	// Client is the server-to-server HTTP client used for the token,
	// deauthorize and revoke legs. It must not follow redirects.
	Client *http.Client
	// Logger receives handler-level diagnostics. nil means slog.Default.
	Logger *slog.Logger
	// Now supplies the reference time. nil means time.Now.
	Now func() time.Time
}

// Register installs every OAuth route on mux.
//
// The routes use Go 1.22 method+pattern syntax. "POST /api/v3/oauth/token" is
// registered as an exact path so that ServeMux's most-specific-pattern rule
// makes it win over the "/api/v3/" reverse-proxy catch-all registered by main.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+pathAuthorize, h.Authorize)
	mux.HandleFunc("GET "+pathMobileAuthorize, h.MobileAuthorize)
	mux.HandleFunc("GET /oauth/callback", h.Callback)
	mux.HandleFunc("POST /oauth/token", h.Token)
	mux.HandleFunc("POST "+pathToken, h.Token)
	mux.HandleFunc("POST "+pathDeauthorize, h.Deauthorize)
	mux.HandleFunc("POST "+pathRevoke, h.Revoke)
}

// now returns the handler's reference time.
func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// logger returns the handler's logger, never nil.
func (h *Handler) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// httpClient returns the handler's outbound client, never nil.
func (h *Handler) httpClient() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return http.DefaultClient
}

// ring returns the key ring to seal and open envelopes with: the explicitly
// configured one if present, otherwise the live configuration's.
func (h *Handler) ring(cfg *config.Config) seal.Ring {
	if len(h.Ring) > 0 {
		return h.Ring
	}
	if cfg == nil {
		return nil
	}
	r := make(seal.Ring, 0, len(cfg.StateKeys))
	for _, k := range cfg.StateKeys {
		r = append(r, seal.Key{KID: k.KID, Key: k.Key})
	}
	return r
}

// upstreamURL builds an absolute upstream URL for path. The host always comes
// from configuration, never from request input.
func upstreamURL(cfg *config.Config, path string) (*url.URL, error) {
	base, err := url.Parse(cfg.UpstreamBaseURL)
	if err != nil {
		return nil, err
	}
	if !base.IsAbs() || base.Host == "" {
		return nil, errors.New("oauth: upstream base URL is not absolute")
	}
	return base.JoinPath(path), nil
}

// firstParam returns the first value of key and whether the key was present at
// all. The distinction matters: "?error=" is an error response with an empty
// value, which must still be forwarded, while a missing "error" is not.
func firstParam(v url.Values, key string) (string, bool) {
	vs, ok := v[key]
	if !ok || len(vs) == 0 {
		return "", ok
	}
	return vs[0], true
}

// writeInternal reports a proxy-internal failure (a key ring that cannot sign,
// an unusable upstream base URL) on a browser-facing route.
//
// It renders the same minimal page as a client error but with a 500 status, so
// the browser sees an honest server-side failure and no request data is
// reflected back. These paths are unreachable with a configuration that passed
// startup validation.
func writeInternal(w http.ResponseWriter) {
	w.Header().Set("Content-Type", fault.ContentTypeHTML)
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = io.WriteString(w, internalErrorPage)
}

const internalErrorPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>500 Internal Server Error</title>
</head>
<body>
<h1>500 Internal Server Error</h1>
<p>The request could not be processed.</p>
</body>
</html>
`

// relay executes req and copies the upstream response through verbatim.
//
// The status code and body are reproduced byte-for-byte and the body is
// streamed, never buffered or re-marshalled, so undocumented fields (and the
// athlete object) survive intact. Only Content-Type and Content-Length are
// copied from the upstream headers: the proxy's own hardening headers, already
// set by the middleware, must not be overwritten by Strava's.
//
// It returns the relayed status code, or 0 when the call failed — in which case
// a 502 or 504 Fault has already been written.
func (h *Handler) relay(w http.ResponseWriter, req *http.Request, route string) int {
	resp, err := h.httpClient().Do(req)
	if err != nil {
		kind := "unavailable"
		if isTimeout(err) {
			kind = "timeout"
		}
		metrics.Inc(metrics.UpstreamErrors, kind)
		h.logger().Warn("upstream call failed", "route", route, "kind", kind, "error", redactURL(err))
		if kind == "timeout" {
			fault.WriteUpstreamTimeout(w)
		} else {
			fault.WriteUpstreamUnavailable(w)
		}
		return 0
	}
	defer resp.Body.Close()

	hdr := w.Header()
	for _, name := range []string{"Content-Type", "Content-Length"} {
		if v := resp.Header.Get(name); v != "" {
			hdr.Set(name, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		h.logger().Warn("relaying upstream body failed", "route", route, "error", err)
	}
	return resp.StatusCode
}

// isTimeout reports whether err is a deadline or network timeout rather than a
// connection-level failure. The two map to different Fault shapes (504 vs 502).
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	// http.Client's overall timeout surfaces as an *url.Error whose message
	// ends in "(Client.Timeout exceeded ...)" and whose Timeout() is true; the
	// net.Error branch above catches it. This string check is a last resort for
	// transports that wrap the cause opaquely.
	return strings.Contains(err.Error(), "Client.Timeout")
}

// redactURL strips the URL from a transport error before it reaches the log.
// Upstream URLs carry no secrets today (credentials travel in bodies), but the
// logger must not become the one place where that assumption is load-bearing.
func redactURL(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Op + " " + ue.Err.Error()
	}
	return err.Error()
}
