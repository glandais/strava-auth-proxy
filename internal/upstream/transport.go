// Package upstream holds everything the proxy needs to talk to Strava: a
// hardened, shared *http.Transport, the server-to-server *http.Client used by
// the OAuth handlers, and the /api/v3/* reverse proxy.
//
// Two invariants are load-bearing and asserted by tests:
//
//   - Certificate verification can never be turned off: no opt-out field, no
//     flag, no env var. TLS 1.2 is the floor. A test enforces that the
//     skip-verify knob is not even named in the package's non-test source.
//   - Compression is disabled at the transport level (DisableCompression), so
//     the caller's own Accept-Encoding is forwarded verbatim and a gzip body
//     reaches the caller still compressed, with Content-Encoding and
//     Content-Length intact.
package upstream

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// Transport tuning constants. They are deliberately modest: the proxy makes at
// most one attempt per caller request (no retries, no circuit breaker), so a
// stuck upstream must surface as a 504 rather than pile up connections.
const (
	// DialTimeout bounds TCP connection establishment to Strava.
	DialTimeout = 5 * time.Second
	// KeepAlive is the TCP keep-alive probe interval for pooled connections.
	KeepAlive = 30 * time.Second
	// TLSHandshakeTimeout bounds the TLS handshake.
	TLSHandshakeTimeout = 10 * time.Second
	// ResponseHeaderTimeout bounds the wait for Strava's response headers
	// after the request body has been written. Body streaming afterwards is
	// unbounded on purpose: activity streams and uploads can be large.
	ResponseHeaderTimeout = 30 * time.Second
	// ExpectContinueTimeout bounds the 100-continue wait.
	ExpectContinueTimeout = 1 * time.Second
	// IdleConnTimeout is how long a pooled idle connection is kept.
	IdleConnTimeout = 90 * time.Second
	// MaxIdleConns is the total idle connection pool size.
	MaxIdleConns = 100
	// MaxIdleConnsPerHost sizes the pool for the single upstream host the
	// proxy ever talks to, so bursts do not churn TLS handshakes.
	MaxIdleConnsPerHost = 32
	// ClientTimeout is the overall deadline for the OAuth handlers'
	// server-to-server calls (token exchange, revoke, deauthorize).
	ClientTimeout = 15 * time.Second
)

// NewTransport returns the hardened *http.Transport used for every
// proxy-to-Strava connection.
//
// TLS is pinned to a 1.2 minimum and certificate verification is always on.
// DisableCompression is set so that response bodies pass through exactly as
// Strava encoded them; the reverse proxy relies on this for gzip fidelity.
func NewTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   DialTimeout,
			KeepAlive: KeepAlive,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		MaxIdleConns:          MaxIdleConns,
		MaxIdleConnsPerHost:   MaxIdleConnsPerHost,
		IdleConnTimeout:       IdleConnTimeout,
		TLSHandshakeTimeout:   TLSHandshakeTimeout,
		ResponseHeaderTimeout: ResponseHeaderTimeout,
		ExpectContinueTimeout: ExpectContinueTimeout,
	}
}

// NewClient returns the *http.Client used by the OAuth handlers for
// server-to-server calls to Strava.
//
// Redirects are never followed: a 3xx from a token endpoint is a contract
// change, not something to chase, and following one could replay real
// credentials to another host. The response is returned to the caller as-is
// via http.ErrUseLastResponse. The overall timeout covers connect, request,
// response headers and body.
func NewClient() *http.Client {
	return &http.Client{
		Transport: NewTransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: ClientTimeout,
	}
}
