package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glandais/strava-auth-proxy/internal/config"
	"github.com/glandais/strava-auth-proxy/internal/upstream"
)

const (
	virtualID     = "90001"
	virtualSecret = "virtual-secret"
	realID        = "12345"
	realSecret    = "real-strava-secret"
)

// fakeUpstream stands in for Strava. It records every request it receives so a
// test can prove which leg of the proxy handled a call.
type fakeUpstream struct {
	mu   sync.Mutex
	hits []hit
	srv  *httptest.Server
}

type hit struct {
	method string
	path   string
	form   url.Values
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	f := &fakeUpstream{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.hits = append(f.hits, hit{method: r.Method, path: r.URL.Path, form: r.Form})
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Set("X-RateLimit-Usage", "1,1")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeUpstream) recorded() []hit {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]hit(nil), f.hits...)
}

// testConfig builds a fully valid configuration without touching the
// environment, so the tests never depend on process-wide state.
func testConfig(upstreamBase string) *config.Config {
	digest := sha256.Sum256([]byte(virtualSecret))
	return &config.Config{
		StravaClientID:     realID,
		StravaClientSecret: config.NewSecret(realSecret),
		PublicURL:          "https://proxy.example",
		UpstreamBaseURL:    upstreamBase,
		ListenAddr:         "127.0.0.1:0",
		AdminAddr:          "127.0.0.1:0",
		DevAllowHTTP:       true,
		StateKeys:          []config.StateKey{{KID: "k1", Key: bytes.Repeat([]byte{0x5a}, 32)}},
		StateTTL:           15 * time.Minute,
		Clients: map[string]*config.Client{
			virtualID: {
				ID:           virtualID,
				SecretSHA256: digest,
				RedirectURIs: []string{"https://app.example/cb"},
			},
		},
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// newPublicHandler wires the caller-facing handler exactly as newApp does.
func newPublicHandler(t *testing.T, f *fakeUpstream) http.Handler {
	t.Helper()
	cfg := testConfig(f.srv.URL)
	base, err := url.Parse(cfg.UpstreamBaseURL)
	if err != nil {
		t.Fatalf("parsing upstream base URL: %v", err)
	}
	client := upstream.NewClient()
	proxy := upstream.NewProxy(base, client.Transport, discardLogger())
	return publicHandler(config.NewHolder(cfg), client, proxy, discardLogger())
}

func postForm(path string, form url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// The exact "POST /api/v3/oauth/token" route must beat the "/api/v3/"
// catch-all: if the catch-all swallowed it, the caller's virtual credentials
// would be forwarded to Strava unchanged and the exchange would fail — or
// worse, leak the virtual secret upstream.
func TestTokenRouteWinsOverAPICatchAll(t *testing.T) {
	for _, path := range []string{"/oauth/token", "/api/v3/oauth/token"} {
		t.Run(path, func(t *testing.T) {
			f := newFakeUpstream(t)
			h := newPublicHandler(t, f)

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, postForm(path, url.Values{
				"client_id":     {virtualID},
				"client_secret": {virtualSecret},
				"grant_type":    {"refresh_token"},
				"refresh_token": {"R"},
			}))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
			}
			hits := f.recorded()
			if len(hits) != 1 {
				t.Fatalf("upstream hits = %d, want exactly 1: %+v", len(hits), hits)
			}
			// The OAuth handler always posts to Strava's canonical token path
			// with the REAL credentials substituted. A blind proxy pass-through
			// would have forwarded the virtual ones.
			if got := hits[0].form.Get("client_id"); got != realID {
				t.Errorf("upstream client_id = %q, want the real application id %q "+
					"(request was proxied instead of handled)", got, realID)
			}
			if got := hits[0].form.Get("client_secret"); got != realSecret {
				t.Errorf("upstream client_secret was not substituted")
			}
			if got := hits[0].path; got != "/api/v3/oauth/token" {
				t.Errorf("upstream path = %q, want /api/v3/oauth/token", got)
			}
		})
	}
}

// The token route is handled locally end-to-end: a bad virtual client_id is
// rejected by the proxy and never reaches Strava.
func TestTokenRouteRejectsUnknownClientWithoutContactingUpstream(t *testing.T) {
	f := newFakeUpstream(t)
	h := newPublicHandler(t, f)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postForm("/api/v3/oauth/token", url.Values{
		"client_id":  {"99999"},
		"grant_type": {"refresh_token"},
	}))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %q)", rec.Code, rec.Body.String())
	}
	var body struct {
		Errors []struct{ Resource, Field, Code string } `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding fault: %v (body %q)", err, rec.Body.String())
	}
	if len(body.Errors) != 1 || body.Errors[0].Field != "client_id" {
		t.Errorf("fault = %+v, want a client_id fault", body.Errors)
	}
	if hits := f.recorded(); len(hits) != 0 {
		t.Errorf("upstream contacted on a rejected token request: %+v", hits)
	}
}

// Everything else under /api/v3/ still reaches the reverse proxy.
func TestAPICatchAllIsProxied(t *testing.T) {
	f := newFakeUpstream(t)
	h := newPublicHandler(t, f)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v3/athlete", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	hits := f.recorded()
	if len(hits) != 1 || hits[0].path != "/api/v3/athlete" {
		t.Fatalf("upstream hits = %+v, want one GET /api/v3/athlete", hits)
	}
	if got := rec.Header().Get("X-RateLimit-Usage"); got != "1,1" {
		t.Errorf("X-RateLimit-Usage = %q, want it relayed verbatim", got)
	}
}

// The hardening headers cover the OAuth surface — including the token endpoint
// living under /api/v3/ — and must not rewrite the cache semantics of proxied
// API responses.
func TestSecurityHeadersScopedToOAuthSurface(t *testing.T) {
	f := newFakeUpstream(t)
	h := newPublicHandler(t, f)

	for _, tc := range []struct {
		name     string
		req      *http.Request
		hardened bool
	}{
		{"authorize", httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=nope", nil), true},
		{"callback", httptest.NewRequest(http.MethodGet, "/oauth/callback?state=bogus", nil), true},
		{"token", postForm("/oauth/token", url.Values{"client_id": {"nope"}}), true},
		{"api token", postForm("/api/v3/oauth/token", url.Values{"client_id": {"nope"}}), true},
		{"proxied api", httptest.NewRequest(http.MethodGet, "/api/v3/athlete", nil), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, tc.req)

			gotRef := rec.Header().Get("Referrer-Policy")
			gotCache := rec.Header().Get("Cache-Control")
			if tc.hardened {
				if gotRef != "no-referrer" {
					t.Errorf("Referrer-Policy = %q, want no-referrer", gotRef)
				}
				if gotCache != "no-store" {
					t.Errorf("Cache-Control = %q, want no-store", gotCache)
				}
				return
			}
			if gotRef != "" {
				t.Errorf("Referrer-Policy = %q on a proxied response, want none", gotRef)
			}
			if gotCache != "max-age=60" {
				t.Errorf("Cache-Control = %q, want the upstream value relayed verbatim", gotCache)
			}
		})
	}
}

func TestIsOAuthSurface(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/oauth/authorize", true},
		{"/oauth/mobile/authorize", true},
		{"/oauth/callback", true},
		{"/oauth/token", true},
		{"/oauth/revoke", true},
		{"/api/v3/oauth/token", true},
		{"/api/v3/athlete", false},
		{"/api/v3/oauth/tokens", false},
		{"/healthz", false},
	} {
		if got := isOAuthSurface(tc.path); got != tc.want {
			t.Errorf("isOAuthSurface(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// The public listener refuses plain HTTP unless the operator opts in.
func TestCheckListenerSecurity(t *testing.T) {
	for _, tc := range []struct {
		name             string
		cert, key        string
		devAllowHTTP     bool
		wantPlainRefused bool
	}{
		{name: "no tls, no opt-in", wantPlainRefused: true},
		{name: "cert without key", cert: "/tls.crt", wantPlainRefused: true},
		{name: "key without cert", key: "/tls.key", wantPlainRefused: true},
		{name: "tls pair", cert: "/tls.crt", key: "/tls.key"},
		{name: "dev opt-in", devAllowHTTP: true},
		{name: "tls pair and opt-in", cert: "/tls.crt", key: "/tls.key", devAllowHTTP: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig("https://www.strava.com")
			cfg.TLSCertFile, cfg.TLSKeyFile, cfg.DevAllowHTTP = tc.cert, tc.key, tc.devAllowHTTP

			err := checkListenerSecurity(cfg)
			if tc.wantPlainRefused {
				if !errors.Is(err, errPlainHTTPRefused) {
					t.Fatalf("err = %v, want errPlainHTTPRefused", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
		})
	}
}

// newApp must refuse to bind at all when the public listener would be plain
// HTTP without the opt-in.
func TestNewAppRefusesInsecurePublicListener(t *testing.T) {
	cfg := testConfig("https://www.strava.com")
	cfg.DevAllowHTTP = false

	a, err := newApp(config.NewHolder(cfg), discardLogger())
	if !errors.Is(err, errPlainHTTPRefused) {
		t.Fatalf("err = %v, want errPlainHTTPRefused", err)
	}
	if a != nil {
		a.close()
		t.Fatal("newApp returned an app despite refusing to start")
	}
}

func TestAdminHandler(t *testing.T) {
	h := adminHandler()

	for _, tc := range []struct {
		method, path string
		wantStatus   int
		wantBody     string
	}{
		{http.MethodGet, "/healthz", http.StatusOK, "ok\n"},
		{http.MethodGet, "/readyz", http.StatusOK, "ready\n"},
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed, ""},
		{http.MethodGet, "/nope", http.StatusNotFound, ""},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if tc.wantBody != "" && rec.Body.String() != tc.wantBody {
				t.Errorf("body = %q, want %q", rec.Body.String(), tc.wantBody)
			}
		})
	}

	t.Run("GET /metrics", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var vars map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &vars); err != nil {
			t.Fatalf("metrics body is not expvar JSON: %v", err)
		}
		for _, name := range []string{"oauth_callbacks_total", "token_exchanges_total", "upstream_errors_total"} {
			if _, ok := vars[name]; !ok {
				t.Errorf("counter %q missing from /metrics", name)
			}
		}
	})
}

// Readiness must never depend on Strava: a Strava outage yields clean 502s to
// callers, not a replica evicted from the load balancer.
func TestReadyzDoesNotProbeUpstream(t *testing.T) {
	f := newFakeUpstream(t)
	// The admin surface has no upstream wiring at all; assert the fake stays
	// untouched to keep that property from silently regressing.
	rec := httptest.NewRecorder()
	adminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if hits := f.recorded(); len(hits) != 0 {
		t.Errorf("/readyz contacted upstream: %+v", hits)
	}
}

// End-to-end on real sockets: both listeners come up, serve, and shut down
// cleanly when the context is cancelled.
func TestServeStartsAndShutsDown(t *testing.T) {
	f := newFakeUpstream(t)
	a, err := newApp(config.NewHolder(testConfig(f.srv.URL)), discardLogger())
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	defer a.close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.serve(ctx) }()

	adminURL := "http://" + a.adminLn.Addr().String()
	publicURL := "http://" + a.publicLn.Addr().String()
	client := &http.Client{Timeout: 5 * time.Second}

	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := client.Get(adminURL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200 (body %q)", path, resp.StatusCode, body)
		}
	}

	resp, err := client.Get(publicURL + "/api/v3/athlete")
	if err != nil {
		t.Fatalf("GET /api/v3/athlete: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /api/v3/athlete = %d, want 200", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned %v, want nil on graceful shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return after context cancellation")
	}
}

func TestNewLogger(t *testing.T) {
	for _, tc := range []struct {
		level     string
		wantDebug bool
	}{
		{"", false},
		{"info", false},
		{"INFO", false},
		{"debug", true},
		{"DEBUG", true},
		{"nonsense", false},
	} {
		t.Run("level="+tc.level, func(t *testing.T) {
			var buf bytes.Buffer
			newLogger(&buf, tc.level).Debug("hello")
			if got := strings.Contains(buf.String(), "hello"); got != tc.wantDebug {
				t.Errorf("debug logged = %v, want %v (output %q)", got, tc.wantDebug, buf.String())
			}
		})
	}
}

func TestRingFrom(t *testing.T) {
	cfg := testConfig("https://www.strava.com")
	cfg.StateKeys = append(cfg.StateKeys, config.StateKey{KID: "k0", Key: bytes.Repeat([]byte{1}, 32)})

	ring := ringFrom(cfg)
	if len(ring) != 2 {
		t.Fatalf("ring length = %d, want 2", len(ring))
	}
	if ring[0].KID != "k1" || ring[1].KID != "k0" {
		t.Errorf("kids = %v, want the configured order preserved (newest first)", kids(ring))
	}
	if !bytes.Equal(ring[0].Key, cfg.StateKeys[0].Key) {
		t.Error("key bytes were not carried over")
	}
	if ringFrom(nil) != nil {
		t.Error("ringFrom(nil) should be nil")
	}
}
