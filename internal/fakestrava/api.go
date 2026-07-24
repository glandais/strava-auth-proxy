package fakestrava

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Paths with special behaviour under /api/v3/. Everything else behaves like
// PathEcho.
const (
	// PathEcho reports the received request back as JSON.
	PathEcho = "/api/v3/echo"
	// PathGzip returns the same JSON, gzip-encoded.
	PathGzip = "/api/v3/gzip"
	// PathStream returns a chunked, incrementally flushed response.
	PathStream = "/api/v3/stream"
	// PathRateLimited returns the canonical 429 Fault.
	PathRateLimited = "/api/v3/ratelimited"
	// PathUnauthorized returns the canonical 401 Fault.
	PathUnauthorized = "/api/v3/unauthorized"
)

// Echo is the JSON body returned by the /api/v3/* echo handlers. It reports
// what the fake actually received, which is how tests assert that the reverse
// proxy forwarded the Authorization header byte-for-byte and stripped the
// X-Forwarded-* family.
type Echo struct {
	Method   string              `json:"method"`
	Path     string              `json:"path"`
	RawQuery string              `json:"raw_query"`
	Host     string              `json:"host"`
	Proto    string              `json:"proto"`
	Headers  map[string][]string `json:"headers"`
	Form     map[string][]string `json:"form"`
	Body     string              `json:"body"`
}

// handleAPI serves the /api/v3/* catch-all. Every response carries the
// configured rate-limit headers, in their configured casing.
func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	s.writeRateLimitHeaders(w)

	switch r.URL.Path {
	case PathGzip:
		s.writeGzip(w, r)
	case PathStream:
		s.writeStream(w, r)
	case PathRateLimited:
		writeFault(w, http.StatusTooManyRequests, "Rate Limit Exceeded", faultError{"Application", "rate limit", "exceeded"})
	case PathUnauthorized:
		writeFault(w, http.StatusUnauthorized, "Authorization Error", faultError{"Athlete", "access_token", "invalid"})
	default:
		writeJSON(w, http.StatusOK, newEcho(r))
	}
}

// writeGzip emits the echo body gzip-encoded, so tests can prove the proxy
// relays compressed bodies without decompressing them.
func (s *Server) writeGzip(w http.ResponseWriter, r *http.Request) {
	body, err := json.Marshal(newEcho(r))
	if err != nil {
		http.Error(w, "fakestrava: marshal failed", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(body); err != nil {
		http.Error(w, "fakestrava: gzip failed", http.StatusInternalServerError)
		return
	}
	if err := zw.Close(); err != nil {
		http.Error(w, "fakestrava: gzip close failed", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Content-Encoding", "gzip")
	h.Set("Content-Length", fmt.Sprint(buf.Len()))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// writeStream emits newline-delimited JSON chunks, flushing after each one and
// pausing in between. No Content-Length is set, so the response is chunked.
func (s *Server) writeStream(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	chunks, delay := s.streamChunks, s.streamDelay
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	for i := range chunks {
		if _, err := fmt.Fprintf(w, "{\"chunk\":%d}\n", i); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		if delay > 0 && i < chunks-1 {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(delay):
			}
		}
	}
}

// writeRateLimitHeaders copies the configured headers into the response map
// directly: net/http writes the keys as spelled, so Strava's non-canonical
// casing survives to the wire.
func (s *Server) writeRateLimitHeaders(w http.ResponseWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dst := w.Header()
	for k, vs := range s.rateLimitHeaders {
		dst[k] = append([]string(nil), vs...)
	}
}

// newEcho snapshots a request, body included: the recording wrapper hands the
// handler an intact, replayable body.
func newEcho(r *http.Request) Echo {
	body, _ := io.ReadAll(r.Body)
	return Echo{
		Method:   r.Method,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
		Host:     r.Host,
		Proto:    r.Proto,
		Headers:  r.Header,
		Form:     r.Form,
		Body:     string(body),
	}
}
