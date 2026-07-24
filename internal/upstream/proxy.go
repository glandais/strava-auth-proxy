package upstream

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/glandais/strava-auth-proxy/internal/fault"
	"github.com/glandais/strava-auth-proxy/internal/metrics"
)

// Metric keys published under metrics.UpstreamErrors.
const (
	// KindTimeout counts upstream calls that exceeded a deadline (504).
	KindTimeout = "timeout"
	// KindUnavailable counts upstream calls that failed to complete for any
	// other reason: DNS, connect, TLS, reset, malformed response (502).
	KindUnavailable = "unavailable"
)

// forwardedHeaders are stripped from every outbound request.
//
// The proxy never calls ProxyRequest.SetXForwarded either: Strava sees the
// proxy as the client, caller topology is not leaked upstream, and a caller
// cannot spoof origin metadata by sending its own X-Forwarded-For.
var forwardedHeaders = []string{
	"Forwarded",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
}

// NewProxy returns the /api/v3/* catch-all reverse proxy targeting base.
//
// base must be non-nil and carry a scheme and host; it is the only source of
// the upstream address, which is never derived from request input (the
// non-SSRF invariant). rt may be nil, in which case NewTransport is used.
// logger may be nil, in which case slog.Default is used.
//
// Behaviour:
//
//   - Host is rewritten to base.Host; the inbound path is joined onto base's
//     path with escaping preserved, and the query string is passed through
//     byte-for-byte.
//   - Inbound Forwarded / X-Forwarded-* headers are removed.
//   - Authorization is forwarded untouched and is never read or logged.
//   - FlushInterval -1 flushes immediately, so chunked upstream responses
//     (activity streams) reach the caller incrementally.
//   - Response headers pass through untouched apart from the hop-by-hop set
//     RFC 7230 requires stripping, so X-RateLimit-* / X-ReadRateLimit-* and
//     Strava Fault bodies are relayed verbatim in any casing.
//   - Failures become a proxy-minted Fault: 504 on timeout, 502 otherwise. A
//     caller that disconnects mid-flight is not an error: nothing is written
//     and nothing is logged at error level.
func NewProxy(base *url.URL, rt http.RoundTripper, logger *slog.Logger) http.Handler {
	if base == nil {
		panic("upstream: NewProxy requires a non-nil base URL")
	}
	if base.Scheme == "" || base.Host == "" {
		panic("upstream: NewProxy requires an absolute base URL with scheme and host")
	}
	if rt == nil {
		rt = NewTransport()
	}
	if logger == nil {
		logger = slog.Default()
	}
	target := *base // defensive copy: callers may mutate their URL afterwards

	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			for _, h := range forwardedHeaders {
				r.Out.Header.Del(h)
			}
			// SetURL joins target path + inbound path (preserving
			// percent-encoding via RawPath) and merges query strings.
			r.SetURL(&target)
			// SetURL clears Out.Host so the Host header follows
			// Out.URL.Host; set it explicitly for clarity and so the
			// intent survives any future SetURL change.
			r.Out.Host = target.Host
		},
		Transport:     rt,
		FlushInterval: -1,
		ErrorLog:      log.New(logWriter{logger: logger}, "", 0),
		ErrorHandler:  errorHandler(logger),
	}
	return rp
}

// errorHandler builds the ReverseProxy ErrorHandler: it classifies the
// transport error, counts it, logs it without leaking the request URL, and
// writes the matching Strava-shaped Fault.
func errorHandler(logger *slog.Logger) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		if isCanceled(r, err) {
			// The caller went away. The upstream call was cancelled with
			// it; there is no one left to write to and nothing worth
			// reporting as a failure.
			logger.Debug("upstream request cancelled by client",
				"method", r.Method, "path", r.URL.Path)
			return
		}
		if IsTimeout(err) {
			metrics.Inc(metrics.UpstreamErrors, KindTimeout)
			logger.Error("upstream timeout",
				"method", r.Method, "path", r.URL.Path, "error", redactErr(err))
			fault.WriteUpstreamTimeout(w)
			return
		}
		metrics.Inc(metrics.UpstreamErrors, KindUnavailable)
		logger.Error("upstream unavailable",
			"method", r.Method, "path", r.URL.Path, "error", redactErr(err))
		fault.WriteUpstreamUnavailable(w)
	}
}

// IsTimeout reports whether err is a deadline or timeout failure, as opposed
// to a connect/TLS/reset failure. It is exported so the OAuth handlers can
// classify their own server-to-server call failures the same way.
func IsTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}

// isCanceled reports whether the failure is the caller hanging up rather than
// an upstream fault. Both the error chain and the inbound request context are
// consulted: depending on where cancellation lands, the transport may report
// context.Canceled or a generic "request canceled" error.
func isCanceled(r *http.Request, err error) bool {
	if errors.Is(err, context.Canceled) {
		return true
	}
	if r != nil && errors.Is(r.Context().Err(), context.Canceled) {
		return true
	}
	return false
}

// redactErr strips the request URL from *url.Error values before logging.
//
// The transport wraps failures in *url.Error, whose Error string embeds the
// full URL including the query string. Query strings on proxied routes may
// carry caller data, so only the underlying cause is logged.
func redactErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Op + ": " + ue.Err.Error()
	}
	return err.Error()
}

// logWriter adapts httputil.ReverseProxy's *log.Logger error sink onto slog.
// ReverseProxy uses it for body-copy and panic-suppression diagnostics; those
// go out at warn level, keeping the process on a single structured log stream.
type logWriter struct{ logger *slog.Logger }

func (w logWriter) Write(p []byte) (int, error) {
	w.logger.Warn("reverse proxy", "msg", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
