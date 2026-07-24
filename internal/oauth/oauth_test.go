package oauth_test

import (
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glandais/strava-auth-proxy/internal/config"
	"github.com/glandais/strava-auth-proxy/internal/oauth"
	"github.com/glandais/strava-auth-proxy/internal/seal"
)

// Fixed identities shared by every test in the package.
const (
	realClientID     = "12345"
	realClientSecret = "REAL-STRAVA-SECRET-do-not-leak"

	virtualID     = "90001"
	virtualSecret = "virtual-secret-90001"
	virtualRU     = "https://app.example/cb"

	nonceID     = "90002"
	nonceSecret = "virtual-secret-90002"
	nonceRU     = "https://nonce.example/cb"

	otherID     = "90003"
	otherSecret = "virtual-secret-90003"
	otherRU     = "https://other.example/cb"
)

// fixedNow is the reference instant used by every handler under test.
var fixedNow = time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)

// stateKey is the single ring key; 32 bytes, the configured minimum.
var stateKey = []byte("0123456789abcdef0123456789abcdef")

// recorded is one request captured by the fake Strava server.
type recorded struct {
	Method string
	Path   string
	Query  url.Values
	Header http.Header
	Body   string
	Form   url.Values
}

// fakeStrava is a stand-in for www.strava.com. Handlers are per-path and fully
// programmable so a test can assert exactly what the proxy sent and control
// exactly what comes back.
type fakeStrava struct {
	srv *httptest.Server

	mu       sync.Mutex
	requests []recorded

	// respond, when set, produces the response for every request.
	respond func(w http.ResponseWriter, r *http.Request)
}

func newFakeStrava(t *testing.T) *fakeStrava {
	t.Helper()
	f := &fakeStrava{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		f.mu.Lock()
		f.requests = append(f.requests, recorded{
			Method: r.Method,
			Path:   r.URL.Path,
			Query:  r.URL.Query(),
			Header: r.Header.Clone(),
			Body:   string(body),
			Form:   form,
		})
		f.mu.Unlock()

		if f.respond != nil {
			f.respond(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeStrava) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *fakeStrava) last(t *testing.T) recorded {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		t.Fatal("fake Strava received no request")
	}
	return f.requests[len(f.requests)-1]
}

// testConfig builds a fully populated configuration pointing at upstreamBase.
func testConfig(upstreamBase string) *config.Config {
	mk := func(id, secret, ru string, nonce bool) *config.Client {
		return &config.Client{
			ID:                 id,
			SecretSHA256:       sha256.Sum256([]byte(secret)),
			RedirectURIs:       []string{ru},
			RequireNonceCookie: nonce,
		}
	}
	return &config.Config{
		StravaClientID:     realClientID,
		StravaClientSecret: config.NewSecret(realClientSecret),
		PublicURL:          "https://proxy.example",
		UpstreamBaseURL:    upstreamBase,
		ListenAddr:         ":8443",
		AdminAddr:          "127.0.0.1:9090",
		DevAllowHTTP:       true,
		StateKeys:          []config.StateKey{{KID: "k1", Key: stateKey}},
		StateTTL:           15 * time.Minute,
		Clients: map[string]*config.Client{
			virtualID: mk(virtualID, virtualSecret, virtualRU, false),
			nonceID:   mk(nonceID, nonceSecret, nonceRU, true),
			otherID:   mk(otherID, otherSecret, otherRU, false),
		},
	}
}

// newHandler returns a Handler wired to holder with a deterministic clock.
func newHandler(holder *config.Holder) *oauth.Handler {
	return &oauth.Handler{
		Cfg:    holder,
		Client: &http.Client{Timeout: 5 * time.Second},
		Now:    func() time.Time { return fixedNow },
	}
}

// newTestSetup returns a fake Strava, the live config holder and a handler
// mounted on a ServeMux (so route patterns are exercised, not just methods).
func newTestSetup(t *testing.T) (*fakeStrava, *config.Holder, http.Handler) {
	t.Helper()
	fake := newFakeStrava(t)
	holder := config.NewHolder(testConfig(fake.srv.URL))
	mux := http.NewServeMux()
	newHandler(holder).Register(mux)
	return fake, holder, mux
}

// testRing is the ring the handlers use, for minting tokens inside tests.
var testRing = seal.Ring{{KID: "k1", Key: stateKey}}

func sealState(t *testing.T, p seal.StatePayload) string {
	t.Helper()
	tok, err := testRing.Seal(seal.DomainState, p)
	if err != nil {
		t.Fatalf("sealing state: %v", err)
	}
	return tok
}

func sealCode(t *testing.T, p seal.CodePayload) string {
	t.Helper()
	tok, err := testRing.Seal(seal.DomainCode, p)
	if err != nil {
		t.Fatalf("sealing code: %v", err)
	}
	return tok
}

// do runs one request against h and returns the recorder.
func do(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// postForm builds a form-encoded POST request.
func postForm(path string, form url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// location parses the Location header of a redirect response.
func location(t *testing.T, rec *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (body: %s)", rec.Code, rec.Body.String())
	}
	raw := rec.Header().Get("Location")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing Location %q: %v", raw, err)
	}
	return u
}

// assertNoSecret fails if the real Strava secret appears anywhere in the
// response the proxy wrote.
func assertNoSecret(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if strings.Contains(rec.Body.String(), realClientSecret) {
		t.Error("real Strava secret leaked into the response body")
	}
	for name, values := range rec.Header() {
		for _, v := range values {
			if strings.Contains(v, realClientSecret) {
				t.Errorf("real Strava secret leaked into response header %s", name)
			}
		}
	}
}
