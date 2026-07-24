package integration

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glandais/strava-auth-proxy/internal/fakestrava"
)

// bearerToken exercises every character class a Strava access token can carry,
// so a proxy that "cleaned up" the header would be caught.
const bearerToken = "Bearer aBcD.1234-_~+/=eyJhbGciOiJub25lIn0"

func decodeEcho(t *testing.T, body []byte) fakestrava.Echo {
	t.Helper()
	var e fakestrava.Echo
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("decoding echo body: %v (body: %s)", err, body)
	}
	return e
}

// TestAPIPassThrough covers DESIGN.md §2.6: the Authorization header reaches
// Strava byte-for-byte, caller forwarding metadata does not reach it at all,
// the Host is rewritten, and the query string and body survive unchanged.
func TestAPIPassThrough(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	rawQuery := "before=1234567890&keys=time%2Clatlng&key_by_type=true&odd=%2F%20%26%3D%3F"
	res := h.get(h.URL+"/api/v3/echo?"+rawQuery, func(r *http.Request) {
		r.Header.Set("Authorization", bearerToken)
		r.Header.Set("X-Forwarded-For", "203.0.113.9")
		r.Header.Set("X-Forwarded-Host", "caller.example")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("Forwarded", "for=203.0.113.9;proto=https")
		r.Header.Set("Accept-Language", "fr-FR")
	})
	assertStatus(t, res, http.StatusOK)

	echo := decodeEcho(t, res.Body)

	if got := echo.Headers["Authorization"]; len(got) != 1 || got[0] != bearerToken {
		t.Errorf("upstream Authorization = %q, want exactly %q", got, bearerToken)
	}
	if got := h.Fake.LastAuthHeader(); got != bearerToken {
		t.Errorf("fake recorded Authorization %q, want %q", got, bearerToken)
	}
	for _, name := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded"} {
		if v, ok := echo.Headers[name]; ok {
			t.Errorf("%s reached Strava with value %q; caller topology must be stripped", name, v)
		}
	}
	if got, want := echo.RawQuery, rawQuery; got != want {
		t.Errorf("upstream query = %q, want %q", got, want)
	}
	if got, want := echo.Path, "/api/v3/echo"; got != want {
		t.Errorf("upstream path = %q, want %q", got, want)
	}
	fakeHost := strings.TrimPrefix(h.Fake.URL, "http://")
	if echo.Host != fakeHost {
		t.Errorf("upstream Host header = %q, want %q", echo.Host, fakeHost)
	}
	if got := echo.Headers["Accept-Language"]; len(got) != 1 || got[0] != "fr-FR" {
		t.Errorf("Accept-Language = %q, want [fr-FR]", got)
	}

	// The proxy's OAuth hardening headers belong to the OAuth surface only:
	// rewriting Strava's cache semantics on /api/v3 would not be a verbatim
	// relay.
	if got := res.Header.Get("Cache-Control"); got == "no-store" {
		t.Error("the proxy injected Cache-Control: no-store into a relayed /api/v3 response")
	}
}

// TestAPIPassThroughPostBody proves request bodies stream through untouched.
func TestAPIPassThroughPostBody(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	const body = `{"name":"Ride ☃","type":"Ride","elapsed_time":3600}`
	req, err := http.NewRequest(http.MethodPost, h.URL+"/api/v3/activities", strings.NewReader(body))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", bearerToken)

	res := h.do(req)
	assertStatus(t, res, http.StatusOK)
	echo := decodeEcho(t, res.Body)
	if echo.Body != body {
		t.Errorf("upstream body = %q, want %q", echo.Body, body)
	}
	if echo.Method != http.MethodPost {
		t.Errorf("upstream method = %q, want POST", echo.Method)
	}
}

// TestAPIGzipPassThrough covers the DisableCompression invariant: a gzip body
// reaches the caller still compressed, with Content-Encoding and Content-Length
// intact.
func TestAPIGzipPassThrough(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	res := h.get(h.URL+fakestrava.PathGzip, func(r *http.Request) {
		r.Header.Set("Accept-Encoding", "gzip")
		r.Header.Set("Authorization", bearerToken)
	})
	assertStatus(t, res, http.StatusOK)

	if got := res.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if got, want := res.Header.Get("Content-Length"), strconv.Itoa(len(res.Body)); got != want {
		t.Errorf("Content-Length = %q but the body is %s bytes", got, want)
	}
	if !bytes.HasPrefix(res.Body, []byte{0x1f, 0x8b}) {
		t.Fatalf("body is not gzip-framed: %x", res.Body[:min(8, len(res.Body))])
	}

	zr, err := gzip.NewReader(bytes.NewReader(res.Body))
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	defer zr.Close()
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("reading gunzipped body: %v", err)
	}
	echo := decodeEcho(t, plain)
	if echo.Path != fakestrava.PathGzip {
		t.Errorf("gunzipped echo path = %q, want %q", echo.Path, fakestrava.PathGzip)
	}
	// The caller's own Accept-Encoding must be what Strava saw.
	if got := echo.Headers["Accept-Encoding"]; len(got) != 1 || got[0] != "gzip" {
		t.Errorf("upstream Accept-Encoding = %q, want [gzip]", got)
	}
}

// TestAPIRateLimitHeadersPreserved covers the rate-limit fidelity requirement.
//
// Header *values* are asserted, not their wire casing: Go's HTTP client
// canonicalises incoming header names before the proxy ever sees them, so
// "X-RateLimit-Limit" is relayed as "X-Ratelimit-Limit". Header names are
// case-insensitive by RFC 9110 and every client library looks them up that way,
// which is what "in any casing" means here.
func TestAPIRateLimitHeadersPreserved(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	t.Run("defaults", func(t *testing.T) {
		res := h.get(h.URL + "/api/v3/echo")
		assertStatus(t, res, http.StatusOK)
		for name, want := range map[string]string{
			"X-RateLimit-Limit":     "600,30000",
			"X-RateLimit-Usage":     "314,27536",
			"X-ReadRateLimit-Limit": "300,15000",
			"X-ReadRateLimit-Usage": "50,100",
		} {
			if got := res.Header.Get(name); got != want {
				t.Errorf("%s = %q, want %q", name, got, want)
			}
		}
	})

	t.Run("unusual casing", func(t *testing.T) {
		h.Fake.SetRateLimitHeaders(http.Header{
			"x-ratelimit-limit":      {"100,1000"},
			"X-READRATELIMIT-USAGE":  {"7,9"},
			"X-Some-Future-Strava-H": {"tomorrow"},
		})
		t.Cleanup(func() { h.Fake.SetRateLimitHeaders(nil) })

		res := h.get(h.URL + "/api/v3/echo")
		assertStatus(t, res, http.StatusOK)
		for name, want := range map[string]string{
			"X-RateLimit-Limit":      "100,1000",
			"X-ReadRateLimit-Usage":  "7,9",
			"X-Some-Future-Strava-H": "tomorrow",
		} {
			if got := res.Header.Get(name); got != want {
				t.Errorf("%s = %q, want %q", name, got, want)
			}
		}
	})
}

// TestAPIFaultBodiesRelayedVerbatim covers 429/401 pass-through.
func TestAPIFaultBodiesRelayedVerbatim(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	tests := []struct {
		path   string
		status int
		body   string
	}{
		{
			path:   fakestrava.PathRateLimited,
			status: http.StatusTooManyRequests,
			body:   `{"message":"Rate Limit Exceeded","errors":[{"resource":"Application","field":"rate limit","code":"exceeded"}]}`,
		},
		{
			path:   fakestrava.PathUnauthorized,
			status: http.StatusUnauthorized,
			body:   `{"message":"Authorization Error","errors":[{"resource":"Athlete","field":"access_token","code":"invalid"}]}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			res := h.get(h.URL + tc.path)
			assertStatus(t, res, tc.status)
			if string(res.Body) != tc.body {
				t.Errorf("body =\n  %s\nwant\n  %s", res.Body, tc.body)
			}
			// Rate-limit headers accompany even the error responses.
			if res.Header.Get("X-RateLimit-Limit") == "" {
				t.Error("rate-limit headers were dropped from an error response")
			}
		})
	}
}

// TestAPIStreamIsFlushedIncrementally covers FlushInterval -1: the caller must
// see each chunk as Strava emits it, not one buffered blob at the end. This is
// what makes large activity-stream downloads usable.
func TestAPIStreamIsFlushedIncrementally(t *testing.T) {
	t.Parallel()

	const (
		chunks = 4
		delay  = 150 * time.Millisecond
	)
	h := newHarness(t)
	h.Fake.SetStream(chunks, delay)

	req, err := http.NewRequest(http.MethodGet, h.URL+fakestrava.PathStream, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatalf("GET stream: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("Content-Length") != "" {
		t.Error("a chunked upstream response acquired a Content-Length")
	}

	br := bufio.NewReader(resp.Body)
	start := time.Now()
	arrivals := make([]time.Duration, 0, chunks)
	for i := range chunks {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading chunk %d: %v", i, err)
		}
		arrivals = append(arrivals, time.Since(start))
		if want := "{\"chunk\":" + strconv.Itoa(i) + "}\n"; line != want {
			t.Errorf("chunk %d = %q, want %q", i, line, want)
		}
	}

	// A buffering proxy delivers every chunk at once, so the first arrival
	// would sit right next to the last. The comparison is relative on purpose:
	// it does not depend on how loaded the machine running the test is.
	total := arrivals[chunks-1]
	if total < delay {
		t.Fatalf("the whole stream arrived in %s, so the fake never actually paced it", total)
	}
	if arrivals[0] > total/2 {
		t.Errorf("first chunk at %s of a %s stream; that is what a buffering proxy looks like",
			arrivals[0], total)
	}
}

// TestTokenRouteWinsOverCatchAll covers the ServeMux precedence note in
// DESIGN.md §2.6: POST /api/v3/oauth/token is handled locally, never forwarded
// with the caller's virtual credentials attached.
func TestTokenRouteWinsOverCatchAll(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	res := h.postForm(h.URL+"/api/v3/oauth/token", url.Values{
		"client_id":     {"99999"},
		"client_secret": {"nope"},
		"grant_type":    {"authorization_code"},
		"code":          {"whatever"},
	})
	// A proxy-minted fault, which only the local handler can produce.
	assertFault(t, res, http.StatusBadRequest, faultInvalidClientID)
	if got := h.Fake.TokenRequests(); got != 0 {
		t.Errorf("the request reached Strava (%d token requests); the catch-all won the route", got)
	}
	assertOAuthHardening(t, res)
}
