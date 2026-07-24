// Package httpmid holds the proxy's HTTP middleware: response hardening
// headers and a deliberately forgetful access logger.
//
// Both middlewares exist for the same reason: OAuth secrets travel in URLs.
// An authorization code arrives on /oauth/callback as a query parameter and a
// virtual client secret can arrive on /oauth/token the same way, so anything
// that persists or forwards a full URL is a credential leak. [SecurityHeaders]
// closes the browser-side channels (referrer, shared caches) and [AccessLog]
// closes the operator-side one by never writing a query string, header, cookie
// or body to the log — only the method, the route pattern, the path, the
// outcome, and the virtual client id a handler chose to publish through
// [SetClientID].
package httpmid

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// Header names and values set by [SecurityHeaders].
const (
	// HeaderReferrerPolicy stops browsers echoing a callback URL (and the
	// authorization code in it) into a third-party Referer header.
	HeaderReferrerPolicy = "Referrer-Policy"
	// ReferrerPolicyValue is the policy applied to every response.
	ReferrerPolicyValue = "no-referrer"

	// HeaderCacheControl keeps token and callback responses out of shared
	// and on-disk caches.
	HeaderCacheControl = "Cache-Control"
	// CacheControlValue is the caching policy applied to every response.
	CacheControlValue = "no-store"
)

// RedactedQuery is logged in place of a request's query string whenever one is
// present. The query string itself is never logged, in whole or in part.
const RedactedQuery = "?<redacted>"

// maxLoggedPathLen bounds how much of a request path reaches the log. Routed
// requests have short fixed paths; a long path means an unrouted probe, and
// truncating it keeps a caller from inflating log volume at will.
const maxLoggedPathLen = 256

// SecurityHeaders sets the proxy's response hardening headers on every
// response passing through next.
//
// The headers are written before next runs, because the header map is frozen
// once a handler calls WriteHeader (explicitly or implicitly, via the first
// Write). Setting them up front means they survive every exit path a handler
// can take: a 302 to the caller's redirect URI, an early error page, or a
// streamed upstream response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set(HeaderReferrerPolicy, ReferrerPolicyValue)
		h.Set(HeaderCacheControl, CacheControlValue)
		next.ServeHTTP(w, r)
	})
}

// clientIDKey is the context key under which AccessLog installs its holder.
type clientIDKey struct{}

// clientIDHolder is a mutable cell reachable from the request context.
//
// A handler learns the virtual client id in the middle of the request, long
// after the context was built, so it cannot hand the value back through a
// plain context value: context.WithValue would produce a new context the
// middleware never sees. A pointer installed up front and mutated in place is
// the escape hatch. The mutex is not decorative — a handler may set the id
// from a goroutine other than the one AccessLog reads it on.
type clientIDHolder struct {
	mu sync.Mutex
	id string
}

func (h *clientIDHolder) set(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.id = id
}

func (h *clientIDHolder) get() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.id
}

// SetClientID records the virtual client id of the request so the access-log
// line for it carries a client_id field.
//
// Handlers call it as soon as they have authenticated or resolved a client. It
// is a no-op for a nil request, an empty id, or a request that did not pass
// through [AccessLog], so instrumenting a handler can never fail or panic. The
// id is a configured, non-secret identifier; never pass a secret to it.
func SetClientID(r *http.Request, id string) {
	if r == nil || id == "" {
		return
	}
	h, ok := r.Context().Value(clientIDKey{}).(*clientIDHolder)
	if !ok {
		return
	}
	h.set(id)
}

// AccessLog logs one structured record per request handled by next.
//
// The record carries the request method, the ServeMux pattern that matched
// (empty for unrouted requests), the request path, the response status, the
// number of body bytes written, the wall-clock latency, and the virtual client
// id if a handler published one through [SetClientID]. When the request URL
// carries a query string, the fixed marker [RedactedQuery] is logged instead of
// its content: the query string of an OAuth request routinely holds an
// authorization code, a caller state, or a client secret. Headers, cookies and
// bodies are never logged either.
//
// Requests that failed server-side (status 500 and above) are logged at warn
// level; everything else at info. A nil logger falls back to [slog.Default].
func AccessLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lg := logger
		if lg == nil {
			lg = slog.Default()
		}

		holder := new(clientIDHolder)
		r = r.WithContext(context.WithValue(r.Context(), clientIDKey{}, holder))

		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rec, r)
		elapsed := time.Since(start)

		// r.Pattern is populated by http.ServeMux on the very request value
		// passed to next, so it is readable here (Go 1.22+). It is a
		// server-owned string, never caller-controlled.
		attrs := []slog.Attr{
			slog.String("method", r.Method),
			slog.String("pattern", r.Pattern),
			slog.String("path", safePath(r)),
			slog.Int("status", rec.status),
			slog.Int64("bytes", rec.bytes),
			slog.Duration("latency", elapsed),
		}
		if r.URL != nil && r.URL.RawQuery != "" {
			attrs = append(attrs, slog.String("query", RedactedQuery))
		}
		if id := holder.get(); id != "" {
			attrs = append(attrs, slog.String("client_id", id))
		}

		level := slog.LevelInfo
		if rec.status >= http.StatusInternalServerError {
			level = slog.LevelWarn
		}
		lg.LogAttrs(r.Context(), level, "http request", attrs...)
	})
}

// safePath returns the request path, sanitised for logging: control bytes are
// replaced so a caller cannot forge log structure with newlines, and the result
// is truncated to maxLoggedPathLen. The query string is never consulted.
func safePath(r *http.Request) string {
	if r.URL == nil {
		return ""
	}
	p := r.URL.Path
	if len(p) > maxLoggedPathLen {
		p = p[:maxLoggedPathLen] + "…"
	}
	clean := make([]byte, 0, len(p))
	for i := range len(p) {
		if c := p[i]; c < 0x20 || c == 0x7f {
			clean = append(clean, '?')
			continue
		}
		clean = append(clean, p[i])
	}
	return string(clean)
}

// recorder wraps an http.ResponseWriter to observe the status code and the
// number of body bytes written. It observes only: every call is passed through
// untouched, so a wrapped handler behaves exactly as it would unwrapped.
type recorder struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

// WriteHeader records the first final status code and forwards the call.
//
// 1xx responses are informational: net/http permits any number of them before
// the final status, so they are forwarded without being recorded.
func (rec *recorder) WriteHeader(status int) {
	if status >= 100 && status < 200 {
		rec.ResponseWriter.WriteHeader(status)
		return
	}
	if !rec.wroteHeader {
		rec.status = status
		rec.wroteHeader = true
	}
	rec.ResponseWriter.WriteHeader(status)
}

// Write forwards the body bytes and counts those actually written.
func (rec *recorder) Write(b []byte) (int, error) {
	rec.wroteHeader = true
	n, err := rec.ResponseWriter.Write(b)
	rec.bytes += int64(n)
	return n, err
}

// Unwrap exposes the underlying writer to http.ResponseController, which is how
// httputil.ReverseProxy flushes streamed responses and sets deadlines.
func (rec *recorder) Unwrap() http.ResponseWriter { return rec.ResponseWriter }

// Flush forwards to the underlying writer when it supports flushing, so
// wrapping a handler never turns a streamed response into a buffered one.
func (rec *recorder) Flush() {
	if f, ok := rec.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack forwards to the underlying writer when it supports hijacking.
func (rec *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := rec.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.ErrUnsupported
	}
	return h.Hijack()
}
