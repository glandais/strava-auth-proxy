// Package fakestrava provides a configurable, in-process fake of the Strava
// API for tests.
//
// It mirrors the contract recorded in docs/STRAVA-CONTRACT.md: the two
// authorize endpoints, both token endpoints (authorization_code and
// refresh_token grants), the legacy deauthorize endpoint, the RFC 7009-shaped
// revoke endpoint, and an /api/v3/* echo surface that can emit rate-limit
// headers, gzip bodies and chunked streamed responses.
//
// Typical use, pointing the proxy at the fake through the injectable upstream
// base URL:
//
//	fake := fakestrava.New(t, "12345", "real-strava-secret")
//	cfg.UpstreamBaseURL = fake.URL
//
// Every knob is guarded by a mutex and may be changed at any time, including
// while requests are in flight. Every received request is recorded, so tests
// can assert on the exact method, path, headers and form the proxy sent.
//
// The fake is deliberately strict about the *real* application credentials —
// that is the whole point of the proxy's credential substitution — and
// deliberately lax about everything the proxy forwards verbatim (scope,
// response_type, approval_prompt, unknown parameters), which it echoes or
// ignores rather than validating.
package fakestrava

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// Access-token lifetime reported by the token endpoints, in seconds. Matches
// Strava's documented six hours.
const accessTokenTTL = 21600

// Default response knobs.
const (
	defaultStreamChunks = 3
	defaultStreamDelay  = 5 * time.Millisecond
)

// RecordedRequest is one request the fake received.
//
// Header is a clone taken before dispatch. Form holds the merged query-string
// and form-body values (as net/http's Request.ParseForm produces them) for
// requests whose body is form-encoded; Body holds the raw, unconsumed body.
type RecordedRequest struct {
	Method   string
	Path     string
	RawQuery string
	Header   http.Header
	Form     url.Values
	Body     []byte
}

// Server is a running fake Strava. The embedded *httptest.Server exposes URL,
// Client and Close; Close is registered with t.Cleanup by New.
//
// All accessors and mutators are safe for concurrent use.
type Server struct {
	*httptest.Server

	realClientID     string
	realClientSecret string

	mu                 sync.Mutex
	grantedScope       string
	authorizeError     string
	rotateRefresh      bool
	hang               time.Duration
	tokenRequests      int
	lastAuthHeader     string
	lastRequestHeaders http.Header
	requests           []RecordedRequest
	athlete            json.RawMessage
	rateLimitHeaders   http.Header
	streamChunks       int
	streamDelay        time.Duration

	seq           int
	codes         map[string]bool // minted authorization code -> already used
	refreshTokens map[string]bool // issued refresh token -> still valid
}

// New starts a fake Strava that accepts realClientID/realClientSecret as the
// real application's credentials, and registers its shutdown with t.Cleanup.
func New(t *testing.T, realClientID, realClientSecret string) *Server {
	t.Helper()

	s := &Server{
		realClientID:     realClientID,
		realClientSecret: realClientSecret,
		athlete:          json.RawMessage(defaultAthleteJSON),
		rateLimitHeaders: defaultRateLimitHeaders(),
		streamChunks:     defaultStreamChunks,
		streamDelay:      defaultStreamDelay,
		codes:            make(map[string]bool),
		refreshTokens:    make(map[string]bool),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth/authorize", s.record(s.handleAuthorize))
	mux.HandleFunc("GET /oauth/mobile/authorize", s.record(s.handleAuthorize))
	// Both token paths accept both grant types, as the live service does.
	// The exact path wins over the /api/v3/ catch-all below.
	mux.HandleFunc("POST /api/v3/oauth/token", s.record(s.handleToken))
	mux.HandleFunc("POST /oauth/token", s.record(s.handleToken))
	mux.HandleFunc("POST /oauth/deauthorize", s.record(s.handleDeauthorize))
	mux.HandleFunc("POST /oauth/revoke", s.record(s.handleRevoke))
	mux.HandleFunc("/api/v3/", s.record(s.handleAPI))
	mux.HandleFunc("/", s.record(s.handleNotFound))

	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Server.Close)
	return s
}

// SetGrantedScope overrides the scope reported back by the authorize step. The
// empty string (the default) means "echo the requested scope", normalised to
// the comma-delimited form Strava uses in the callback.
func (s *Server) SetGrantedScope(scope string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grantedScope = scope
}

// SetAuthorizeError makes the authorize endpoints redirect back with
// error=<value> and no code. The empty string (the default) restores the
// success path.
func (s *Server) SetAuthorizeError(errValue string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authorizeError = errValue
}

// SetRotateRefresh controls whether the refresh_token grant issues a new
// refresh token (invalidating the presented one) or returns it unchanged.
func (s *Server) SetRotateRefresh(rotate bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotateRefresh = rotate
}

// SetHang makes every handler sleep for d before responding, which is how
// tests exercise the proxy's upstream timeout paths. Zero disables it.
func (s *Server) SetHang(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hang = d
}

// SetAthleteJSON overrides the athlete object returned by the
// authorization_code grant. Passing nil or an empty value restores the default
// SummaryAthlete. The bytes are emitted verbatim, so tests can plant
// undocumented fields and assert that the proxy relays them intact.
func (s *Server) SetAthleteJSON(raw []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(raw) == 0 {
		s.athlete = json.RawMessage(defaultAthleteJSON)
		return
	}
	s.athlete = json.RawMessage(append([]byte(nil), raw...))
}

// SetRateLimitHeaders replaces the headers emitted on every /api/v3/*
// response. Keys are written to the wire exactly as spelled here — the
// defaults use Strava's own non-canonical casing (X-RateLimit-Limit,
// X-ReadRateLimit-Usage, ...) so tests can prove the proxy does not rewrite
// them. Passing nil restores the defaults.
func (s *Server) SetRateLimitHeaders(h http.Header) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h == nil {
		s.rateLimitHeaders = defaultRateLimitHeaders()
		return
	}
	s.rateLimitHeaders = h.Clone()
}

// SetStream configures /api/v3/stream: how many chunks it writes and how long
// it pauses between them. Non-positive values keep the current setting.
func (s *Server) SetStream(chunks int, delay time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if chunks > 0 {
		s.streamChunks = chunks
	}
	if delay >= 0 {
		s.streamDelay = delay
	}
}

// TokenRequests reports how many requests either token endpoint has received,
// including the ones rejected for bad credentials. It is the assertion behind
// "the proxy makes exactly one upstream attempt and never retries".
func (s *Server) TokenRequests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokenRequests
}

// LastAuthHeader returns the Authorization header of the most recent request
// that carried one, verbatim. Requests without the header leave it untouched.
func (s *Server) LastAuthHeader() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastAuthHeader
}

// LastRequestHeaders returns a copy of the headers of the most recent request,
// or nil if none has arrived.
func (s *Server) LastRequestHeaders() http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastRequestHeaders == nil {
		return nil
	}
	return s.lastRequestHeaders.Clone()
}

// clone deep-copies a record, so callers can never mutate the server's own
// copy through a returned snapshot.
func (r RecordedRequest) clone() RecordedRequest {
	out := r
	out.Header = r.Header.Clone()
	out.Form = cloneValues(r.Form)
	out.Body = append([]byte(nil), r.Body...)
	return out
}

// Requests returns a snapshot of every request received so far, oldest first.
func (s *Server) Requests() []RecordedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]RecordedRequest, 0, len(s.requests))
	for _, r := range s.requests {
		out = append(out, r.clone())
	}
	return out
}

// LastRequest returns the most recent recorded request and whether there was
// one.
func (s *Server) LastRequest() (RecordedRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.requests) == 0 {
		return RecordedRequest{}, false
	}
	return s.requests[len(s.requests)-1].clone(), true
}

// RequestsTo returns every recorded request whose path equals path.
func (s *Server) RequestsTo(path string) []RecordedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []RecordedRequest
	for _, r := range s.requests {
		if r.Path == path {
			out = append(out, r.clone())
		}
	}
	return out
}

// Reset clears the recorded requests, the token counter and the last-seen
// headers. Minted codes, issued refresh tokens and the behaviour knobs are
// left alone.
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = nil
	s.tokenRequests = 0
	s.lastAuthHeader = ""
	s.lastRequestHeaders = nil
}

// record wraps a handler with request capture and the configurable hang.
//
// The body is read once, recorded, and handed back to the handler intact, so
// handlers can still call ParseForm (or stream the body) as usual.
func (s *Server) record(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		// Populates r.Form/r.PostForm for form-encoded bodies; a later
		// ParseForm inside the handler is then a no-op.
		_ = r.ParseForm()
		r.Body = io.NopCloser(bytes.NewReader(body))

		rec := RecordedRequest{
			Method:   r.Method,
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
			Header:   r.Header.Clone(),
			Form:     cloneValues(r.Form),
			Body:     body,
		}

		s.mu.Lock()
		s.requests = append(s.requests, rec)
		s.lastRequestHeaders = rec.Header
		if auth := r.Header.Get("Authorization"); auth != "" {
			s.lastAuthHeader = auth
		}
		hang := s.hang
		s.mu.Unlock()

		if hang > 0 {
			time.Sleep(hang)
		}
		next(w, r)
	}
}

// handleNotFound answers anything outside the modelled surface.
func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeFault(w, http.StatusNotFound, "Resource Not Found", faultError{"Resource", "path", "invalid"})
}

// cloneValues deep-copies parsed form values.
func cloneValues(v url.Values) url.Values {
	if v == nil {
		return nil
	}
	out := make(url.Values, len(v))
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// defaultRateLimitHeaders returns Strava's documented rate-limit headers, in
// Strava's own casing. The map is used directly as response headers, and
// net/http writes keys verbatim, so the casing survives to the wire.
func defaultRateLimitHeaders() http.Header {
	return http.Header{
		"X-RateLimit-Limit":     {"600,30000"},
		"X-RateLimit-Usage":     {"314,27536"},
		"X-ReadRateLimit-Limit": {"300,15000"},
		"X-ReadRateLimit-Usage": {"50,100"},
	}
}

// defaultAthleteJSON is a SummaryAthlete as documented in the Swagger spec,
// plus the extra fields live responses carry.
const defaultAthleteJSON = `{
  "id": 227615,
  "resource_state": 2,
  "firstname": "Fake",
  "lastname": "Athlete",
  "profile_medium": "https://example.invalid/athlete/medium.jpg",
  "profile": "https://example.invalid/athlete/large.jpg",
  "city": "Nantes",
  "state": "Pays de la Loire",
  "country": "France",
  "sex": "M",
  "premium": true,
  "summit": true,
  "created_at": "2011-03-19T21:59:57Z",
  "updated_at": "2026-01-02T10:11:12Z",
  "username": "fakeathlete",
  "badge_type_id": 4
}`
