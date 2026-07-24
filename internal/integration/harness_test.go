package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glandais/strava-auth-proxy/internal/config"
	"github.com/glandais/strava-auth-proxy/internal/fakestrava"
	"github.com/glandais/strava-auth-proxy/internal/httpmid"
	"github.com/glandais/strava-auth-proxy/internal/oauth"
	"github.com/glandais/strava-auth-proxy/internal/seal"
	"github.com/glandais/strava-auth-proxy/internal/upstream"
)

// Identities used across the suite.
//
// realClientSecret is the sentinel the secret-leak sweep hunts for: it is
// distinctive enough that a single substring match anywhere in a response or a
// log record is unambiguous evidence of a leak.
const (
	realClientID     = "12345"
	realClientSecret = "REALSECRET-do-not-leak-9f3c"

	clientAID     = "90001"
	clientASecret = "virtual-A-secret-4d19"
	clientBID     = "90002"
	clientBSecret = "virtual-B-secret-c0fe"

	// appRedirectURI is client A's primary callback. appRedirectAltURI already
	// carries a query string, which proves the callback rebuilds the redirect
	// through net/url instead of concatenating strings.
	appRedirectURI    = "https://app.example/strava/cb"
	appRedirectAltURI = "https://app.example/strava/cb?tenant=acme"
	// otherRedirectURI belongs to client B only.
	otherRedirectURI = "https://other.example/oauth/return"
)

// defaultLogSink captures anything the code under test emits through
// slog.Default rather than through an injected logger. It is swept for secrets
// alongside every harness's own logger, so a leak cannot hide by taking the
// default-logger path.
var defaultLogSink = new(syncBuffer)

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(defaultLogSink, &slog.HandlerOptions{Level: slog.LevelDebug})))
	os.Exit(m.Run())
}

// syncBuffer is an io.Writer safe for concurrent use, used as a slog sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// capturedResponse is one response the driver received, recorded in full.
//
// Request holds only the method and path: the query string is deliberately
// excluded, because tests legitimately send virtual credentials there and the
// capture must not become the leak it exists to detect.
type capturedResponse struct {
	Request    string
	StatusLine string
	Header     http.Header
	Body       []byte
}

// recorder accumulates every captured response of one harness.
type recorder struct {
	mu   sync.Mutex
	resp []*capturedResponse
}

func (r *recorder) add(c *capturedResponse) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resp = append(r.resp, c)
}

func (r *recorder) snapshot() []capturedResponse {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]capturedResponse, 0, len(r.resp))
	for _, c := range r.resp {
		out = append(out, capturedResponse{
			Request:    c.Request,
			StatusLine: c.StatusLine,
			Header:     c.Header.Clone(),
			Body:       bytes.Clone(c.Body),
		})
	}
	return out
}

// recordingTransport captures the status line, headers and body of every
// response the driver receives, without buffering: the body is tapped as the
// test reads it, so streaming responses stay streamed.
type recordingTransport struct {
	base http.RoundTripper
	rec  *recorder
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	c := &capturedResponse{
		Request:    req.Method + " " + req.URL.Path,
		StatusLine: resp.Proto + " " + resp.Status,
		Header:     resp.Header.Clone(),
	}
	t.rec.add(c)
	resp.Body = &tapReader{rc: resp.Body, rec: t.rec, c: c}
	return resp, nil
}

// tapReader mirrors everything read from a response body into its capture.
type tapReader struct {
	rc  io.ReadCloser
	rec *recorder
	c   *capturedResponse
}

func (t *tapReader) Read(p []byte) (int, error) {
	n, err := t.rc.Read(p)
	if n > 0 {
		t.rec.mu.Lock()
		t.c.Body = append(t.c.Body, p[:n]...)
		t.rec.mu.Unlock()
	}
	return n, err
}

func (t *tapReader) Close() error { return t.rc.Close() }

// harnessConfig collects the knobs newHarness accepts.
type harnessConfig struct {
	upstreamURL           string
	stateTTL              time.Duration
	clientTimeout         time.Duration
	responseHeaderTimeout time.Duration
	clients               map[string]*config.Client
}

type harnessOpt func(*harnessConfig)

// withUpstream points the proxy at something other than the fake Strava — a
// dead address, or a stub that always fails.
func withUpstream(rawURL string) harnessOpt {
	return func(hc *harnessConfig) { hc.upstreamURL = rawURL }
}

// withClientTimeout shortens the overall deadline of the proxy's
// server-to-server calls so a hanging upstream surfaces as a 504 in test time.
func withClientTimeout(d time.Duration) harnessOpt {
	return func(hc *harnessConfig) { hc.clientTimeout = d }
}

// withResponseHeaderTimeout shortens the reverse proxy's wait for upstream
// response headers, the /api/v3 equivalent of withClientTimeout.
func withResponseHeaderTimeout(d time.Duration) harnessOpt {
	return func(hc *harnessConfig) { hc.responseHeaderTimeout = d }
}

// withStateTTL overrides the sealed-envelope lifetime.
func withStateTTL(d time.Duration) harnessOpt {
	return func(hc *harnessConfig) { hc.stateTTL = d }
}

// harness is one fully wired proxy: fake Strava, the real handler stack, and a
// driver HTTP client that records everything it sees.
type harness struct {
	t *testing.T

	Fake   *fakestrava.Server
	Holder *config.Holder
	Ring   seal.Ring
	URL    string
	Client *http.Client

	logs *syncBuffer
	rec  *recorder
}

// newHarness builds a proxy whose configuration is constructed in process.
//
// The configuration is assembled directly rather than through config.Load so
// that harnesses do not have to mutate process-wide environment variables and
// can therefore run in parallel. TestConfigHotReload covers the config.Load and
// config.Holder.Reload paths, and TestEnvLoadedConfigDrivesTheSameFlow proves
// an env-loaded configuration produces the same flow.
func newHarness(t *testing.T, opts ...harnessOpt) *harness {
	t.Helper()

	hc := &harnessConfig{
		stateTTL:      config.DefaultStateTTL,
		clientTimeout: upstream.ClientTimeout,
	}
	for _, o := range opts {
		o(hc)
	}

	fake := fakestrava.New(t, realClientID, realClientSecret)

	// The public URL has to be known before the configuration is built (it is
	// what the proxy registers with Strava as its callback), and the handler
	// has to be built from that configuration. An unstarted server resolves the
	// circularity: its listener is already bound, so its address is final.
	srv := httptest.NewUnstartedServer(nil)
	publicURL := "http://" + srv.Listener.Addr().String()

	upstreamURL := hc.upstreamURL
	if upstreamURL == "" {
		upstreamURL = fake.URL
	}
	clients := hc.clients
	if clients == nil {
		clients = defaultClients()
	}

	cfg := &config.Config{
		StravaClientID:     realClientID,
		StravaClientSecret: config.NewSecret(realClientSecret),
		PublicURL:          publicURL,
		UpstreamBaseURL:    upstreamURL,
		ListenAddr:         "127.0.0.1:0",
		AdminAddr:          "127.0.0.1:0",
		DevAllowHTTP:       true,
		StateKeys:          testStateKeys(),
		StateTTL:           hc.stateTTL,
		Clients:            clients,
	}

	return startHarness(t, fake, srv, config.NewHolder(cfg), hc)
}

// startHarness wires the handler stack around an already published
// configuration and starts serving. It is shared by newHarness and the
// environment-driven harness used by the hot-reload tests.
func startHarness(t *testing.T, fake *fakestrava.Server, srv *httptest.Server, holder *config.Holder, hc *harnessConfig) *harness {
	t.Helper()

	cfg := holder.Get()
	logs := new(syncBuffer)
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	base, err := url.Parse(cfg.UpstreamBaseURL)
	if err != nil {
		t.Fatalf("parsing upstream base URL %q: %v", cfg.UpstreamBaseURL, err)
	}

	// The real hardened transport and client, with only the deadlines scaled
	// down to test time.
	outbound := upstream.NewClient()
	if hc.clientTimeout > 0 {
		outbound.Timeout = hc.clientTimeout
	}
	if hc.responseHeaderTimeout > 0 {
		outbound.Transport.(*http.Transport).ResponseHeaderTimeout = hc.responseHeaderTimeout
	}
	t.Cleanup(outbound.CloseIdleConnections)

	proxy := upstream.NewProxy(base, outbound.Transport, logger)
	srv.Config.Handler = publicHandler(holder, outbound, proxy, logger)
	srv.Start()
	t.Cleanup(srv.Close)

	rec := new(recorder)
	driverTransport := &http.Transport{
		// The driver stands in for a browser or an app backend, so it must not
		// silently decompress: the gzip pass-through assertion depends on the
		// body arriving exactly as the proxy wrote it.
		DisableCompression: true,
	}
	t.Cleanup(driverTransport.CloseIdleConnections)

	h := &harness{
		t:      t,
		Fake:   fake,
		Holder: holder,
		Ring:   ringOf(cfg),
		URL:    srv.URL,
		Client: &http.Client{
			Transport: &recordingTransport{base: driverTransport, rec: rec},
			// Never follow redirects: every hop of the dance is inspected.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		logs: logs,
		rec:  rec,
	}
	// Registered last so it runs first: the sweep is unconditional, so every
	// scenario in the suite contributes to it (DESIGN.md §6).
	t.Cleanup(h.assertNoSecretLeak)
	return h
}

// publicHandler mirrors cmd/strava-auth-proxy's wiring exactly: the OAuth
// routes on a ServeMux, the /api/v3/ catch-all reverse proxy behind them, the
// hardening headers on the OAuth surface only, and the redacting access log
// around everything.
func publicHandler(holder *config.Holder, client *http.Client, proxy http.Handler, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	h := &oauth.Handler{Cfg: holder, Client: client, Logger: logger}
	h.Register(mux)
	mux.Handle("/api/v3/", proxy)
	return httpmid.AccessLog(logger, oauthSurfaceHeaders(mux))
}

func oauthSurfaceHeaders(next http.Handler) http.Handler {
	hardened := httpmid.SecurityHeaders(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/oauth/") || r.URL.Path == "/api/v3/oauth/token" {
			hardened.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// testStateKeys returns a two-key ring, newest first, mirroring a mid-rotation
// deployment.
func testStateKeys() []config.StateKey {
	return []config.StateKey{
		{KID: "k2", Key: bytes.Repeat([]byte{0x2b}, 32)},
		{KID: "k1", Key: bytes.Repeat([]byte{0x1a}, 32)},
	}
}

// testStateKeySpec renders testStateKeys in the PROXY_STATE_KEYS format.
func testStateKeySpec() string {
	parts := make([]string, 0, 2)
	for _, k := range testStateKeys() {
		parts = append(parts, k.KID+"="+fmt.Sprintf("%x", k.Key))
	}
	return strings.Join(parts, ",")
}

func ringOf(cfg *config.Config) seal.Ring {
	r := make(seal.Ring, 0, len(cfg.StateKeys))
	for _, k := range cfg.StateKeys {
		r = append(r, seal.Key{KID: k.KID, Key: k.Key})
	}
	return r
}

func defaultClients() map[string]*config.Client {
	return map[string]*config.Client{
		clientAID: {
			ID:           clientAID,
			SecretSHA256: sha256.Sum256([]byte(clientASecret)),
			RedirectURIs: []string{appRedirectURI, appRedirectAltURI},
		},
		clientBID: {
			ID:           clientBID,
			SecretSHA256: sha256.Sum256([]byte(clientBSecret)),
			RedirectURIs: []string{otherRedirectURI},
		},
	}
}

// ---------------------------------------------------------------------------
// Driver helpers
// ---------------------------------------------------------------------------

// result is a response with its body already drained.
type result struct {
	*http.Response
	Body []byte
}

func (h *harness) do(req *http.Request) *result {
	h.t.Helper()
	resp, err := h.Client.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatalf("reading body of %s %s: %v", req.Method, req.URL.Path, err)
	}
	return &result{Response: resp, Body: body}
}

func (h *harness) get(rawURL string, mods ...func(*http.Request)) *result {
	h.t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		h.t.Fatalf("building GET request: %v", err)
	}
	for _, m := range mods {
		m(req)
	}
	return h.do(req)
}

func (h *harness) postForm(rawURL string, form url.Values, mods ...func(*http.Request)) *result {
	h.t.Helper()
	body := form.Encode()
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(body))
	if err != nil {
		h.t.Fatalf("building POST request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = int64(len(body))
	for _, m := range mods {
		m(req)
	}
	return h.do(req)
}

// follow issues a GET against the Location of a redirect response.
func (h *harness) follow(res *result) *result {
	h.t.Helper()
	loc := location(h.t, res)
	return h.get(loc.String())
}

// location parses the Location header of a redirect, failing the test if the
// response is not a redirect or carries no usable Location.
func location(t *testing.T, res *result) *url.URL {
	t.Helper()
	if res.StatusCode < 300 || res.StatusCode >= 400 {
		t.Fatalf("want a redirect, got %d: %s", res.StatusCode, res.Body)
	}
	raw := res.Header.Get("Location")
	if raw == "" {
		t.Fatalf("redirect %d carries no Location header", res.StatusCode)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing Location: %v", err)
	}
	return u
}

// authorizeQuery builds a typical caller authorize request for client A.
func authorizeQuery() url.Values {
	return url.Values{
		"client_id":       {clientAID},
		"redirect_uri":    {appRedirectURI},
		"response_type":   {"code"},
		"scope":           {"read,activity:read_all"},
		"approval_prompt": {"auto"},
	}
}

// browserFlow drives the whole browser leg — proxy authorize, fake Strava,
// proxy callback — and returns the callback's response, which is either the
// 302 to the caller's redirect_uri or a 400 page.
func (h *harness) browserFlow(q url.Values) *result {
	h.t.Helper()
	toStrava := h.get(h.URL + "/oauth/authorize?" + q.Encode())
	assertStatus(h.t, toStrava, http.StatusFound)
	toCallback := h.follow(toStrava)
	assertStatus(h.t, toCallback, http.StatusFound)
	return h.follow(toCallback)
}

// wrappedCode drives the browser leg and returns the wrapped authorization code
// the caller would receive.
func (h *harness) wrappedCode(q url.Values) string {
	h.t.Helper()
	final := h.browserFlow(q)
	assertStatus(h.t, final, http.StatusFound)
	code := location(h.t, final).Query().Get("code")
	if code == "" {
		h.t.Fatal("final redirect carries no code")
	}
	return code
}

// exchange posts an authorization_code grant.
func (h *harness) exchange(clientID, secret, code string) *result {
	h.t.Helper()
	return h.postForm(h.URL+"/oauth/token", url.Values{
		"client_id":     {clientID},
		"client_secret": {secret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
	})
}

// refresh posts a refresh_token grant.
func (h *harness) refresh(clientID, secret, refreshToken string) *result {
	h.t.Helper()
	return h.postForm(h.URL+"/oauth/token", url.Values{
		"client_id":     {clientID},
		"client_secret": {secret},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	})
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

func assertStatus(t *testing.T, res *result, want int) {
	t.Helper()
	if res.StatusCode != want {
		t.Fatalf("status = %d, want %d (body: %s)", res.StatusCode, want, res.Body)
	}
}

// assertFault asserts a proxy-minted Strava Fault, byte-for-byte.
func assertFault(t *testing.T, res *result, wantStatus int, wantBody string) {
	t.Helper()
	assertStatus(t, res, wantStatus)
	if got := res.Header.Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json; charset=utf-8", got)
	}
	if string(res.Body) != wantBody {
		t.Errorf("fault body =\n  %s\nwant\n  %s", res.Body, wantBody)
	}
}

// assertNoRedirect asserts the browser-facing 400 page: no Location, no echo of
// the request.
func assertNoRedirect(t *testing.T, res *result) {
	t.Helper()
	assertStatus(t, res, http.StatusBadRequest)
	if loc := res.Header.Get("Location"); loc != "" {
		t.Errorf("400 page must not redirect, got Location %q", loc)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

// assertOAuthHardening asserts the headers DESIGN.md §2 requires on every
// /oauth/* response.
func assertOAuthHardening(t *testing.T, res *result) {
	t.Helper()
	if got := res.Header.Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// Canned Fault bodies, spelled out here rather than built from internal/fault
// so that a change to the writers shows up as an integration failure.
const (
	faultInvalidClientID     = `{"message":"Bad Request","errors":[{"resource":"Application","field":"client_id","code":"invalid"}]}`
	faultInvalidClientSecret = `{"message":"Bad Request","errors":[{"resource":"Application","field":"client_secret","code":"invalid"}]}`
	faultInvalidCode         = `{"message":"Bad Request","errors":[{"resource":"AuthorizationCode","field":"code","code":"invalid"}]}`
	faultUnauthorized        = `{"message":"Authorization Error","errors":[{"resource":"Application","field":"client_id","code":"invalid"}]}`
	faultUpstreamUnavailable = `{"message":"Bad Gateway","errors":[{"resource":"Upstream","field":"strava","code":"unavailable"}]}`
	faultUpstreamTimeout     = `{"message":"Gateway Timeout","errors":[{"resource":"Upstream","field":"strava","code":"timeout"}]}`
)

// ---------------------------------------------------------------------------
// Secret-leak sweep (DESIGN.md §6)
// ---------------------------------------------------------------------------

// tokenPrefixes are the prefixes fakestrava mints its access and refresh tokens
// with. No log record may contain either: DESIGN.md invariant 3 forbids logging
// tokens, and a prefix match catches any partial echo too.
var tokenPrefixes = []string{"fakeaccess", "fakerefresh"}

// assertNoSecretLeak sweeps every captured response and every log record
// produced by this harness for the real Strava application secret, the virtual
// client secrets and raw Strava tokens.
//
// It runs unconditionally at the end of every harness, so every scenario in the
// package feeds it.
func (h *harness) assertNoSecretLeak() {
	h.t.Helper()

	// The revoke leg sends the real credentials upstream as HTTP Basic, so the
	// base64 rendering is swept too: a header echoed back to a caller or into a
	// log would not match the plaintext scan.
	basic := base64.StdEncoding.EncodeToString([]byte(realClientID + ":" + realClientSecret))
	responseSecrets := map[string]string{
		"real Strava client_secret":            realClientSecret,
		"real Strava credentials (HTTP Basic)": basic,
	}

	for _, c := range h.rec.snapshot() {
		blob := c.StatusLine + "\n" + headerString(c.Header) + "\n" + string(c.Body)
		for name, secret := range responseSecrets {
			if strings.Contains(blob, secret) {
				h.t.Errorf("%s leaked in the response to %s (status %s)", name, c.Request, c.StatusLine)
			}
		}
	}

	logSecrets := maps.Clone(responseSecrets)
	logSecrets["virtual client A secret"] = clientASecret
	logSecrets["virtual client B secret"] = clientBSecret

	logs := h.logs.String() + defaultLogSink.String()
	for name, secret := range logSecrets {
		if strings.Contains(logs, secret) {
			h.t.Errorf("%s leaked into a log record", name)
		}
	}
	for _, prefix := range tokenPrefixes {
		if strings.Contains(logs, prefix) {
			h.t.Errorf("a raw Strava token (%q...) leaked into a log record", prefix)
		}
	}
}

func headerString(h http.Header) string {
	var sb strings.Builder
	for _, k := range slices.Sorted(maps.Keys(h)) {
		for _, v := range h[k] {
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}
