package upstream

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"expvar"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/glandais/strava-auth-proxy/internal/metrics"
)

const (
	body502 = `{"message":"Bad Gateway","errors":[{"resource":"Upstream","field":"strava","code":"unavailable"}]}`
	body504 = `{"message":"Gateway Timeout","errors":[{"resource":"Upstream","field":"strava","code":"timeout"}]}`
)

// --- helpers -----------------------------------------------------------

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

// spyHandler records every slog.Record emitted through it.
type spyHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *spyHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *spyHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *spyHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *spyHandler) WithGroup(string) slog.Handler      { return h }

func (h *spyHandler) atLevel(l slog.Level) []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []slog.Record
	for _, r := range h.records {
		if r.Level == l {
			out = append(out, r)
		}
	}
	return out
}

func spyLogger() (*slog.Logger, *spyHandler) {
	h := &spyHandler{}
	return slog.New(h), h
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func upstreamErrCount(t *testing.T, key string) int64 {
	t.Helper()
	v := metrics.UpstreamErrors.Get(key)
	if v == nil {
		return 0
	}
	iv, ok := v.(*expvar.Int)
	if !ok {
		t.Fatalf("metrics key %q is %T, want *expvar.Int", key, v)
	}
	return iv.Value()
}

// recordingUpstream starts a server that captures the last request it saw and
// hands it to fn (which may write the response).
func recordingUpstream(t *testing.T, fn http.HandlerFunc) (*httptest.Server, func() *http.Request) {
	t.Helper()
	var (
		mu   sync.Mutex
		last *http.Request
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		last = r.Clone(context.Background())
		mu.Unlock()
		if fn != nil {
			fn(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, func() *http.Request {
		mu.Lock()
		defer mu.Unlock()
		return last
	}
}

// frontFor starts an httptest server serving the reverse proxy for base.
func frontFor(t *testing.T, base string, rt http.RoundTripper) *httptest.Server {
	t.Helper()
	front := httptest.NewServer(NewProxy(mustURL(t, base), rt, discardLogger()))
	t.Cleanup(front.Close)
	return front
}

// --- rewrite behaviour -------------------------------------------------

func TestProxyRewritesHostHeader(t *testing.T) {
	up, last := recordingUpstream(t, nil)
	front := frontFor(t, up.URL, nil)

	req, err := http.NewRequest(http.MethodGet, front.URL+"/api/v3/athlete", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	upHost := mustURL(t, up.URL).Host
	if got := last().Host; got != upHost {
		t.Errorf("upstream Host = %q, want %q", got, upHost)
	}
	if got := last().Host; got == mustURL(t, front.URL).Host {
		t.Errorf("upstream Host still carries the inbound host %q", got)
	}
}

func TestProxyStripsForwardedHeaders(t *testing.T) {
	up, last := recordingUpstream(t, nil)
	front := frontFor(t, up.URL, nil)

	req, err := http.NewRequest(http.MethodGet, front.URL+"/api/v3/athlete", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("X-Forwarded-Host", "caller.example")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Forwarded", "for=203.0.113.7;host=caller.example;proto=https")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	for _, h := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		if got := last().Header.Values(h); len(got) != 0 {
			t.Errorf("upstream received %s = %v, want it stripped", h, got)
		}
	}
}

func TestProxyForwardsAuthorizationByteIdentical(t *testing.T) {
	const token = "Bearer aBcD.1234-_~+/=eyJ" // deliberately awkward bytes

	up, last := recordingUpstream(t, nil)
	front := frontFor(t, up.URL, nil)

	req, err := http.NewRequest(http.MethodGet, front.URL+"/api/v3/athlete", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if got := last().Header.Get("Authorization"); got != token {
		t.Errorf("upstream Authorization = %q, want %q", got, token)
	}
	if got := last().Header.Values("Authorization"); len(got) != 1 {
		t.Errorf("upstream Authorization values = %v, want exactly one", got)
	}
}

func TestProxyPreservesPathAndQuery(t *testing.T) {
	tests := []struct {
		name      string
		basePath  string
		request   string
		wantPath  string
		wantQuery string
	}{
		{
			name:     "plain path",
			request:  "/api/v3/athlete",
			wantPath: "/api/v3/athlete",
		},
		{
			name:      "query passed through",
			request:   "/api/v3/athlete/activities?page=2&per_page=30",
			wantPath:  "/api/v3/athlete/activities",
			wantQuery: "page=2&per_page=30",
		},
		{
			name:      "encoded path and query survive",
			request:   "/api/v3/segments/a%2Fb%20c/leaderboard?q=%C3%A9t%C3%A9&x=a+b&empty=",
			wantPath:  "/api/v3/segments/a%2Fb%20c/leaderboard",
			wantQuery: "q=%C3%A9t%C3%A9&x=a+b&empty=",
		},
		{
			name:      "base path prefix is joined",
			basePath:  "/strava",
			request:   "/api/v3/athlete?x=1",
			wantPath:  "/strava/api/v3/athlete",
			wantQuery: "x=1",
		},
		{
			name:     "trailing slash preserved",
			request:  "/api/v3/athlete/",
			wantPath: "/api/v3/athlete/",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			up, last := recordingUpstream(t, nil)
			front := frontFor(t, up.URL+tc.basePath, nil)

			resp, err := http.Get(front.URL + tc.request)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()

			got := last()
			if p := got.URL.EscapedPath(); p != tc.wantPath {
				t.Errorf("upstream path = %q, want %q", p, tc.wantPath)
			}
			if q := got.URL.RawQuery; q != tc.wantQuery {
				t.Errorf("upstream query = %q, want %q", q, tc.wantQuery)
			}
		})
	}
}

func TestProxyForwardsMethodAndBody(t *testing.T) {
	const payload = `{"name":"morning ride"}`

	var gotBody []byte
	up, last := recordingUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	})
	front := frontFor(t, up.URL, nil)

	resp, err := http.Post(front.URL+"/api/v3/activities", "application/json", bytes.NewBufferString(payload))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if last().Method != http.MethodPost {
		t.Errorf("upstream method = %q, want POST", last().Method)
	}
	if string(gotBody) != payload {
		t.Errorf("upstream body = %q, want %q", gotBody, payload)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.StatusCode)
	}
}

// --- response fidelity -------------------------------------------------

func TestProxyGzipBodyStaysCompressed(t *testing.T) {
	payload := bytes.Repeat([]byte(`{"id":1234567890,"name":"ride"},`), 64)
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	gz := compressed.Bytes()

	var sawAcceptEncoding string
	up, _ := recordingUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		sawAcceptEncoding = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(gz)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gz)
	})
	front := frontFor(t, up.URL, nil)

	// A client that neither advertises nor transparently decodes gzip on its
	// own, so what arrives is exactly what the proxy relayed.
	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	req, err := http.NewRequest(http.MethodGet, front.URL+"/api/v3/athlete/activities", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if sawAcceptEncoding != "gzip" {
		t.Errorf("upstream Accept-Encoding = %q, want the caller's %q", sawAcceptEncoding, "gzip")
	}
	if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip", got)
	}
	if resp.Uncompressed {
		t.Error("response was transparently decompressed somewhere in the chain")
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, gz) {
		t.Errorf("relayed body differs from the upstream gzip stream (%d vs %d bytes)", len(got), len(gz))
	}
	if cl := resp.Header.Get("Content-Length"); cl != strconv.Itoa(len(gz)) {
		t.Errorf("Content-Length = %q, want %d", cl, len(gz))
	}
	zr, err := gzip.NewReader(bytes.NewReader(got))
	if err != nil {
		t.Fatalf("relayed body is not valid gzip: %v", err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, payload) {
		t.Error("decompressed payload differs from the original")
	}
}

func TestProxyRelaysRateLimitHeaders(t *testing.T) {
	// Strava's docs render these in inconsistent casing; the proxy must relay
	// them whatever the casing is, and callers must find them case-insensitively.
	upHeaders := map[string]string{
		"X-RateLimit-Limit":     "600,30000",
		"X-Ratelimit-Usage":     "314,27536",
		"x-readratelimit-limit": "300,15000",
		"X-ReadRateLimit-Usage": "12,1200",
	}
	up, _ := recordingUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		for k, v := range upHeaders {
			w.Header()[k] = []string{v}
		}
		w.WriteHeader(http.StatusOK)
	})
	front := frontFor(t, up.URL, nil)

	resp, err := http.Get(front.URL + "/api/v3/athlete")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	for _, tc := range []struct{ lookup, want string }{
		{"X-RateLimit-Limit", "600,30000"},
		{"x-ratelimit-usage", "314,27536"},
		{"X-ReadRateLimit-Limit", "300,15000"},
		{"X-READRATELIMIT-USAGE", "12,1200"},
	} {
		if got := resp.Header.Get(tc.lookup); got != tc.want {
			t.Errorf("header %s = %q, want %q", tc.lookup, got, tc.want)
		}
	}
}

func TestProxyRelaysStatusAndFaultBodyVerbatim(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{
			name:   "rate limited",
			status: http.StatusTooManyRequests,
			body:   `{"message":"Rate Limit Exceeded","errors":[{"resource":"Application","field":"rate limit","code":"exceeded"}]}`,
		},
		{
			name:   "unauthorized",
			status: http.StatusUnauthorized,
			body:   `{"message":"Authorization Error","errors":[{"resource":"Athlete","field":"access_token","code":"invalid"}]}`,
		},
		{
			name:   "not found",
			status: http.StatusNotFound,
			body:   `{"message":"Resource Not Found","errors":[{"resource":"Activity","field":"id","code":"invalid"}]}`,
		},
		{
			name:   "no content",
			status: http.StatusNoContent,
			body:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			up, _ := recordingUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.body != "" {
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})
			front := frontFor(t, up.URL, nil)

			resp, err := http.Get(front.URL + "/api/v3/activities/1")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.status {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.body {
				t.Errorf("body = %q, want %q", got, tc.body)
			}
		})
	}
}

func TestProxyStreamsIncrementally(t *testing.T) {
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Error("upstream ResponseWriter is not a Flusher")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "first\n")
		fl.Flush()
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
		_, _ = io.WriteString(w, "second\n")
	}))
	defer up.Close()
	front := frontFor(t, up.URL, nil)

	resp, err := http.Get(front.URL + "/api/v3/activities/1/streams/heartrate")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	br := bufio.NewReader(resp.Body)
	type read struct {
		line string
		err  error
	}
	first := make(chan read, 1)
	go func() {
		l, err := br.ReadString('\n')
		first <- read{l, err}
	}()

	// The second chunk is not written yet, so this line can only arrive if
	// the proxy flushed it through immediately.
	select {
	case r := <-first:
		if r.err != nil {
			t.Fatalf("reading first chunk: %v", r.err)
		}
		if r.line != "first\n" {
			t.Fatalf("first chunk = %q, want %q", r.line, "first\n")
		}
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("first chunk was buffered: nothing arrived before the upstream wrote again")
	}

	close(release)
	rest, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("reading remainder: %v", err)
	}
	if string(rest) != "second\n" {
		t.Errorf("remainder = %q, want %q", rest, "second\n")
	}
}

// --- failure paths -----------------------------------------------------

func TestProxyUpstreamDownWritesUnavailableFault(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // nothing is listening any more

	before := upstreamErrCount(t, KindUnavailable)
	logger, spy := spyLogger()
	front := httptest.NewServer(NewProxy(mustURL(t, deadURL), NewTransport(), logger))
	defer front.Close()

	resp, err := http.Get(front.URL + "/api/v3/athlete")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body502 {
		t.Errorf("body = %q, want %q", got, body502)
	}
	if after := upstreamErrCount(t, KindUnavailable); after != before+1 {
		t.Errorf("upstream_errors_total[%s] = %d, want %d", KindUnavailable, after, before+1)
	}
	if n := len(spy.atLevel(slog.LevelError)); n != 1 {
		t.Errorf("error log records = %d, want 1", n)
	}
}

func TestProxyUpstreamHangWritesTimeoutFault(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer up.Close()

	// A transport whose header wait is far shorter than the upstream's stall.
	rt := NewTransport()
	rt.ResponseHeaderTimeout = 150 * time.Millisecond

	before := upstreamErrCount(t, KindTimeout)
	logger, spy := spyLogger()
	front := httptest.NewServer(NewProxy(mustURL(t, up.URL), rt, logger))
	defer front.Close()

	resp, err := http.Get(front.URL + "/api/v3/athlete")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Errorf("status = %d, want 504", resp.StatusCode)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body504 {
		t.Errorf("body = %q, want %q", got, body504)
	}
	if after := upstreamErrCount(t, KindTimeout); after != before+1 {
		t.Errorf("upstream_errors_total[%s] = %d, want %d", KindTimeout, after, before+1)
	}
	if n := len(spy.atLevel(slog.LevelError)); n != 1 {
		t.Errorf("error log records = %d, want 1", n)
	}
}

func TestProxyContextDeadlineWritesTimeoutFault(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer up.Close()

	handler := NewProxy(mustURL(t, up.URL), NewTransport(), discardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v3/athlete", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusGatewayTimeout {
		t.Errorf("status = %d, want 504", rec.Code)
	}
	if got := rec.Body.String(); got != body504 {
		t.Errorf("body = %q, want %q", got, body504)
	}
}

func TestProxyClientCancellationIsSilent(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer up.Close()

	logger, spy := spyLogger()
	handler := NewProxy(mustURL(t, up.URL), NewTransport(), logger)

	beforeTimeout := upstreamErrCount(t, KindTimeout)
	beforeUnavailable := upstreamErrCount(t, KindUnavailable)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the caller has already hung up
	req := httptest.NewRequest(http.MethodGet, "/api/v3/athlete", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Body.Len() != 0 {
		t.Errorf("body = %q, want nothing written", rec.Body.String())
	}
	if n := len(spy.atLevel(slog.LevelError)); n != 0 {
		t.Errorf("error log records = %d, want 0 for a client cancellation", n)
	}
	if got := upstreamErrCount(t, KindTimeout); got != beforeTimeout {
		t.Errorf("timeout counter moved on a client cancellation: %d -> %d", beforeTimeout, got)
	}
	if got := upstreamErrCount(t, KindUnavailable); got != beforeUnavailable {
		t.Errorf("unavailable counter moved on a client cancellation: %d -> %d", beforeUnavailable, got)
	}
}

func TestNewProxyRejectsUnusableBase(t *testing.T) {
	tests := []struct {
		name string
		base *url.URL
	}{
		{name: "nil", base: nil},
		{name: "no scheme", base: &url.URL{Host: "www.strava.com"}},
		{name: "no host", base: &url.URL{Scheme: "https"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("NewProxy accepted an unusable base URL")
				}
			}()
			_ = NewProxy(tc.base, nil, discardLogger())
		})
	}
}

func TestNewProxyCopiesBaseURL(t *testing.T) {
	up, last := recordingUpstream(t, nil)
	base := mustURL(t, up.URL)
	handler := NewProxy(base, nil, discardLogger())

	// Mutating the caller's URL after construction must not retarget the proxy.
	base.Host = "example.invalid"
	base.Path = "/elsewhere"

	front := httptest.NewServer(handler)
	defer front.Close()

	resp, err := http.Get(front.URL + "/api/v3/athlete")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if got := last().URL.EscapedPath(); got != "/api/v3/athlete" {
		t.Errorf("upstream path = %q, want /api/v3/athlete", got)
	}
}

func TestIsTimeout(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "deadline exceeded", err: context.DeadlineExceeded, want: true},
		{name: "wrapped deadline", err: &url.Error{Op: "Get", URL: "https://x", Err: context.DeadlineExceeded}, want: true},
		{name: "canceled", err: context.Canceled, want: false},
		{name: "connect refused", err: &url.Error{Op: "Get", URL: "https://x", Err: errString("connect: connection refused")}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsTimeout(tc.err); got != tc.want {
				t.Errorf("IsTimeout(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestRedactErrDropsURL(t *testing.T) {
	err := &url.Error{
		Op:  "Post",
		URL: "https://www.strava.com/api/v3/oauth/token?client_secret=supersecret",
		Err: errString("dial tcp: connection refused"),
	}
	got := redactErr(err)
	if bytes.Contains([]byte(got), []byte("client_secret")) {
		t.Errorf("redactErr leaked the query string: %q", got)
	}
	if got != "Post: dial tcp: connection refused" {
		t.Errorf("redactErr = %q", got)
	}
}
