package oauth_test

import (
	"context"
	"expvar"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/glandais/strava-auth-proxy/internal/httpmid"
	"github.com/glandais/strava-auth-proxy/internal/metrics"
)

// Every route Register installs, with a request that reaches its handler.
func TestRegisteredRoutes(t *testing.T) {
	authorizeQuery := url.Values{"client_id": {virtualID}, "redirect_uri": {virtualRU}}.Encode()

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/oauth/authorize?" + authorizeQuery},
		{http.MethodGet, "/oauth/mobile/authorize?" + authorizeQuery},
		{http.MethodGet, "/oauth/callback"},
		{http.MethodPost, "/oauth/token"},
		{http.MethodPost, "/api/v3/oauth/token"},
		{http.MethodPost, "/oauth/deauthorize"},
		{http.MethodPost, "/oauth/revoke"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			_, _, h := newTestSetup(t)
			rec := do(h, httptest.NewRequest(tc.method, tc.path, strings.NewReader("")))
			if rec.Code == http.StatusNotFound {
				t.Errorf("route not registered (404)")
			}
		})
	}
}

// Method mismatches are the mux's business, and must not reach a handler.
func TestWrongMethodIsRejectedByTheMux(t *testing.T) {
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/oauth/authorize"},
		{http.MethodGet, "/oauth/token"},
		{http.MethodGet, "/oauth/revoke"},
		{http.MethodGet, "/oauth/deauthorize"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			fake, _, h := newTestSetup(t)
			rec := do(h, httptest.NewRequest(tc.method, tc.path, nil))
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("status = %d, want 405", rec.Code)
			}
			if fake.count() != 0 {
				t.Error("upstream contacted on a method-mismatched request")
			}
		})
	}
}

// The hardening headers are set by middleware, but they must survive every exit
// path the handlers take — redirect, error page and relayed body alike.
func TestSecurityHeadersSurviveEveryExitPath(t *testing.T) {
	_, _, mux := newTestSetup(t)
	h := httpmid.SecurityHeaders(mux)

	requests := map[string]*http.Request{
		"authorize redirect": httptest.NewRequest(http.MethodGet,
			"/oauth/authorize?"+url.Values{"client_id": {virtualID}, "redirect_uri": {virtualRU}}.Encode(), nil),
		"authorize error page": httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=nope", nil),
		"callback error page":  httptest.NewRequest(http.MethodGet, "/oauth/callback?state=bogus", nil),
		"token fault":          postForm("/oauth/token", url.Values{"client_id": {"nope"}}),
		"token relay": postForm("/oauth/token", url.Values{
			"client_id": {virtualID}, "client_secret": {virtualSecret},
			"grant_type": {"refresh_token"}, "refresh_token": {"R"},
		}),
	}
	for name, r := range requests {
		t.Run(name, func(t *testing.T) {
			rec := do(h, r)
			if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
				t.Errorf("Referrer-Policy = %q", got)
			}
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q", got)
			}
		})
	}
}

// spyHandler captures slog records for assertions.
type spyHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (s *spyHandler) Enabled(context.Context, slog.Level) bool { return true }
func (s *spyHandler) Handle(_ context.Context, r slog.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, r.Clone())
	return nil
}
func (s *spyHandler) WithAttrs([]slog.Attr) slog.Handler { return s }
func (s *spyHandler) WithGroup(string) slog.Handler      { return s }

func (s *spyHandler) attr(name string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rec := range s.records {
		var found string
		var ok bool
		rec.Attrs(func(a slog.Attr) bool {
			if a.Key == name {
				found, ok = a.Value.String(), true
				return false
			}
			return true
		})
		if ok {
			return found, true
		}
	}
	return "", false
}

// Handlers publish the virtual client id so the access-log line carries it —
// the one piece of request identity that is safe to log.
func TestHandlersPublishClientIDToTheAccessLog(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  func(t *testing.T) *http.Request
	}{
		{"authorize", func(*testing.T) *http.Request {
			q := url.Values{"client_id": {virtualID}, "redirect_uri": {virtualRU}}
			return httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
		}},
		{"callback", func(t *testing.T) *http.Request {
			return httptest.NewRequest(http.MethodGet, callbackURL(url.Values{
				"code": {"C"}, "state": {goodState(t)},
			}), nil)
		}},
		{"token", func(*testing.T) *http.Request {
			return postForm("/oauth/token", url.Values{
				"client_id": {virtualID}, "client_secret": {virtualSecret},
				"grant_type": {"refresh_token"}, "refresh_token": {"R"},
			})
		}},
		{"revoke", func(*testing.T) *http.Request {
			r := postForm("/oauth/revoke", url.Values{"token": {"T"}})
			r.SetBasicAuth(virtualID, virtualSecret)
			return r
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, mux := newTestSetup(t)
			spy := &spyHandler{}
			h := httpmid.AccessLog(slog.New(spy), mux)
			do(h, tc.req(t))

			got, ok := spy.attr("client_id")
			if !ok {
				t.Fatal("no client_id attribute reached the access log")
			}
			if got != virtualID {
				t.Errorf("client_id = %q, want %q", got, virtualID)
			}
		})
	}
}

// counter reads an expvar map key as an integer.
func counter(m *expvar.Map, key string) int64 {
	v := m.Get(key)
	if v == nil {
		return 0
	}
	n, err := strconv.ParseInt(v.String(), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func TestMetricsAreRecorded(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    *expvar.Map
		key  string
		req  func(t *testing.T) *http.Request
	}{
		{"callback success", metrics.OAuthCallbacks, "success", func(t *testing.T) *http.Request {
			return httptest.NewRequest(http.MethodGet, callbackURL(url.Values{"code": {"C"}, "state": {goodState(t)}}), nil)
		}},
		{"callback bad state", metrics.OAuthCallbacks, "bad_state", func(*testing.T) *http.Request {
			return httptest.NewRequest(http.MethodGet, "/oauth/callback?state=bogus", nil)
		}},
		{"token success", metrics.TokenExchanges, "refresh_token:success", func(*testing.T) *http.Request {
			return postForm("/oauth/token", url.Values{
				"client_id": {virtualID}, "client_secret": {virtualSecret},
				"grant_type": {"refresh_token"}, "refresh_token": {"R"},
			})
		}},
		{"token bad client", metrics.TokenExchanges, "refresh_token:invalid_client_id", func(*testing.T) *http.Request {
			return postForm("/oauth/token", url.Values{"client_id": {"nope"}, "grant_type": {"refresh_token"}})
		}},
		{"token bad code", metrics.TokenExchanges, "authorization_code:invalid_code", func(*testing.T) *http.Request {
			return postForm("/oauth/token", url.Values{
				"client_id": {virtualID}, "client_secret": {virtualSecret},
				"grant_type": {"authorization_code"}, "code": {"garbage"},
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, h := newTestSetup(t)
			before := counter(tc.m, tc.key)
			do(h, tc.req(t))
			if after := counter(tc.m, tc.key); after != before+1 {
				t.Errorf("counter %q went %d -> %d, want +1", tc.key, before, after)
			}
		})
	}
}

// A caller-chosen grant_type must not become an unbounded expvar key.
func TestMetricsGrantTypeCardinalityIsBounded(t *testing.T) {
	_, _, h := newTestSetup(t)
	before := counter(metrics.TokenExchanges, "other:invalid_client_id")
	for i := range 3 {
		do(h, postForm("/oauth/token", url.Values{
			"client_id": {"nope"}, "grant_type": {"attacker-chosen-" + strconv.Itoa(i)},
		}))
	}
	if after := counter(metrics.TokenExchanges, "other:invalid_client_id"); after != before+3 {
		t.Errorf("counter went %d -> %d, want +3 folded into a single key", before, after)
	}
	metrics.TokenExchanges.Do(func(kv expvar.KeyValue) {
		if strings.Contains(kv.Key, "attacker-chosen") {
			t.Errorf("caller-controlled grant_type became a metrics key: %q", kv.Key)
		}
	})
}

// The three legs compose: the state minted by authorize opens at the callback,
// and the code minted by the callback opens at the token endpoint.
func TestEndToEndFlowWithinTheProxy(t *testing.T) {
	fake, _, h := newTestSetup(t)

	q := url.Values{
		"client_id":    {virtualID},
		"redirect_uri": {virtualRU},
		"scope":        {"read,activity:read_all"},
		"state":        {"caller-csrf-token"},
	}
	authorized := do(h, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	packedState := location(t, authorized).Query().Get("state")

	// Strava redirects the browser back with its own code and granted scope.
	back := url.Values{"code": {"STRAVA-RAW-CODE"}, "scope": {"read"}, "state": {packedState}}
	called := do(h, httptest.NewRequest(http.MethodGet, callbackURL(back), nil))
	final := location(t, called).Query()
	if final.Get("state") != "caller-csrf-token" {
		t.Errorf("state = %q, want the caller's own state back", final.Get("state"))
	}
	if final.Get("scope") != "read" {
		t.Errorf("scope = %q, want the granted subset verbatim", final.Get("scope"))
	}

	// The app exchanges the wrapped code.
	rec := do(h, postForm("/oauth/token", url.Values{
		"client_id":     {virtualID},
		"client_secret": {virtualSecret},
		"grant_type":    {"authorization_code"},
		"code":          {final.Get("code")},
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("exchange status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if got := fake.last(t).Form.Get("code"); got != "STRAVA-RAW-CODE" {
		t.Errorf("upstream code = %q, want Strava's raw code", got)
	}
	assertNoSecret(t, rec)
}
