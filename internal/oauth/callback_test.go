package oauth_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glandais/strava-auth-proxy/internal/config"
	"github.com/glandais/strava-auth-proxy/internal/oauth"
	"github.com/glandais/strava-auth-proxy/internal/seal"
)

// newSetupWith builds a handler over a configuration mutated by fn, which is
// how the tests simulate a SIGHUP hot reload landing mid-flow.
func newSetupWith(t *testing.T, fn func(*config.Config)) http.Handler {
	t.Helper()
	fake := newFakeStrava(t)
	cfg := testConfig(fake.srv.URL)
	fn(cfg)
	mux := http.NewServeMux()
	newHandler(config.NewHolder(cfg)).Register(mux)
	return mux
}

// callbackURL builds a request to /oauth/callback with the given query.
func callbackURL(q url.Values) string { return "/oauth/callback?" + q.Encode() }

// goodState is the packed state a well-formed flow would carry.
func goodState(t *testing.T) string {
	t.Helper()
	return sealState(t, seal.StatePayload{
		CID: virtualID, RU: virtualRU, ST: "caller-state", HasST: true, IAT: fixedNow.Unix(),
	})
}

func TestCallbackSuccess(t *testing.T) {
	_, _, h := newTestSetup(t)

	q := url.Values{
		"code":  {"RAW-STRAVA-CODE"},
		"scope": {"read,activity:read_all"},
		"state": {goodState(t)},
	}
	rec := do(h, httptest.NewRequest(http.MethodGet, callbackURL(q), nil))
	loc := location(t, rec)
	assertNoSecret(t, rec)

	if loc.Scheme+"://"+loc.Host+loc.Path != virtualRU {
		t.Errorf("redirect target = %q, want %q", loc.String(), virtualRU)
	}
	got := loc.Query()
	if got.Get("scope") != "read,activity:read_all" {
		t.Errorf("scope = %q, want Strava's value verbatim", got.Get("scope"))
	}
	if got.Get("state") != "caller-state" {
		t.Errorf("state = %q, want the caller's own state bit-exact", got.Get("state"))
	}
	if got.Get("code") == "RAW-STRAVA-CODE" {
		t.Fatal("raw Strava code handed to the caller unwrapped")
	}
	var cp seal.CodePayload
	if err := testRing.Open(seal.DomainCode, got.Get("code"), &cp, 15*time.Minute, fixedNow); err != nil {
		t.Fatalf("opening the wrapped code: %v", err)
	}
	if cp.CID != virtualID || cp.SC != "RAW-STRAVA-CODE" || cp.IAT != fixedNow.Unix() {
		t.Errorf("wrapped code payload = %+v", cp)
	}
}

func TestCallbackStateAndScopeEchoing(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hasST     bool
		st        string
		scope     []string
		wantState []string // nil means "the param must be absent"
		wantScope []string
	}{
		{"state round-trips", true, "a b+c/&=", []string{"read"}, []string{"a b+c/&="}, []string{"read"}},
		{"empty state still echoed", true, "", []string{"read"}, []string{""}, []string{"read"}},
		{"no state means no state param", false, "", []string{"read"}, nil, []string{"read"}},
		{"no scope from Strava means no scope param", true, "s", nil, []string{"s"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, h := newTestSetup(t)
			state := sealState(t, seal.StatePayload{
				CID: virtualID, RU: virtualRU, ST: tc.st, HasST: tc.hasST, IAT: fixedNow.Unix(),
			})
			q := url.Values{"code": {"C"}, "state": {state}}
			if tc.scope != nil {
				q["scope"] = tc.scope
			}
			got := location(t, do(h, httptest.NewRequest(http.MethodGet, callbackURL(q), nil))).Query()

			if diff := got["state"]; !equalStrings(diff, tc.wantState) {
				t.Errorf("state = %v, want %v", diff, tc.wantState)
			}
			if diff := got["scope"]; !equalStrings(diff, tc.wantScope) {
				t.Errorf("scope = %v, want %v", diff, tc.wantScope)
			}
		})
	}
}

// Strava's error value is forwarded exactly as received, whatever it is.
func TestCallbackForwardsErrorsVerbatim(t *testing.T) {
	for _, errVal := range []string{
		"access_denied",
		"server_error",
		"some_future_strava_error",
		"weird value with spaces & symbols",
		"",
	} {
		t.Run("error="+errVal, func(t *testing.T) {
			_, _, h := newTestSetup(t)
			q := url.Values{
				"error":             {errVal},
				"error_description": {"the athlete said no"},
				"state":             {goodState(t)},
			}
			got := location(t, do(h, httptest.NewRequest(http.MethodGet, callbackURL(q), nil))).Query()

			if _, ok := got["error"]; !ok {
				t.Fatal("error param dropped")
			}
			if got.Get("error") != errVal {
				t.Errorf("error = %q, want %q verbatim", got.Get("error"), errVal)
			}
			if got.Get("error_description") != "the athlete said no" {
				t.Errorf("error_description = %q, want it forwarded", got.Get("error_description"))
			}
			if got.Get("state") != "caller-state" {
				t.Errorf("state = %q, want the caller's state on the error leg too", got.Get("state"))
			}
			if _, ok := got["code"]; ok {
				t.Error("a code was minted on the error leg")
			}
		})
	}
}

// A redirect URI that already carries a query string keeps it; the redirect is
// built by merging parsed values, never by string concatenation.
func TestCallbackMergesExistingQuery(t *testing.T) {
	const ru = "https://app.example/cb?tenant=acme"
	h := newSetupWith(t, func(c *config.Config) {
		c.Clients[virtualID].RedirectURIs = []string{ru}
	})
	state := sealState(t, seal.StatePayload{CID: virtualID, RU: ru, HasST: false, IAT: fixedNow.Unix()})
	q := url.Values{"code": {"C"}, "state": {state}}
	got := location(t, do(h, httptest.NewRequest(http.MethodGet, callbackURL(q), nil))).Query()

	if got.Get("tenant") != "acme" {
		t.Errorf("pre-existing query param lost: %v", got)
	}
	if got.Get("code") == "" {
		t.Error("code missing")
	}
}

func TestCallbackRejections(t *testing.T) {
	otherRing := seal.Ring{{KID: "kX", Key: stateKey}}
	foreignState, err := otherRing.Seal(seal.DomainState, seal.StatePayload{CID: virtualID, RU: virtualRU, IAT: fixedNow.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	valid := func(t *testing.T) string { return goodState(t) }

	for _, tc := range []struct {
		name  string
		state func(t *testing.T) string
		extra url.Values
	}{
		{"missing state", func(*testing.T) string { return "" }, url.Values{"code": {"C"}}},
		{"garbage state", func(*testing.T) string { return "not-a-token" }, url.Values{"code": {"C"}}},
		{"unknown kid", func(*testing.T) string { return foreignState }, url.Values{"code": {"C"}}},
		{"tampered mac", func(t *testing.T) string {
			s := goodState(t)
			i := strings.LastIndex(s, ".") + 1
			return s[:i] + flipChar(s[i]) + s[i+1:]
		}, url.Values{"code": {"C"}}},
		{"tampered payload", func(t *testing.T) string {
			s := goodState(t)
			i := strings.Index(s, ".") + 1
			return s[:i] + flipChar(s[i]) + s[i+1:]
		}, url.Values{"code": {"C"}}},
		{"code token presented as state", func(t *testing.T) string {
			return sealCode(t, seal.CodePayload{CID: virtualID, SC: "C", IAT: fixedNow.Unix()})
		}, url.Values{"code": {"C"}}},
		{"expired state", func(t *testing.T) string {
			return sealState(t, seal.StatePayload{
				CID: virtualID, RU: virtualRU, IAT: fixedNow.Add(-16 * time.Minute).Unix(),
			})
		}, url.Values{"code": {"C"}}},
		{"future state", func(t *testing.T) string {
			return sealState(t, seal.StatePayload{
				CID: virtualID, RU: virtualRU, IAT: fixedNow.Add(5 * time.Minute).Unix(),
			})
		}, url.Values{"code": {"C"}}},
		{"neither code nor error", valid, url.Values{}},
		{"empty code", valid, url.Values{"code": {""}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, h := newTestSetup(t)
			q := url.Values{}
			for k, vs := range tc.extra {
				q[k] = vs
			}
			q.Set("state", tc.state(t))
			rec := do(h, httptest.NewRequest(http.MethodGet, callbackURL(q), nil))

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Errorf("redirected to %q; a rejected callback must never redirect", loc)
			}
			assertNoSecret(t, rec)
		})
	}
}

// A hot reload that removes the client, or drops the redirect URI from its
// allowlist, must strand an in-flight authorization rather than complete it.
func TestCallbackRevalidatesAgainstCurrentConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   func(*config.Config)
	}{
		{"client removed", func(c *config.Config) { delete(c.Clients, virtualID) }},
		{"redirect_uri removed", func(c *config.Config) {
			c.Clients[virtualID].RedirectURIs = []string{"https://app.example/other"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSetupWith(t, tc.fn)
			q := url.Values{"code": {"C"}, "state": {goodState(t)}}
			rec := do(h, httptest.NewRequest(http.MethodGet, callbackURL(q), nil))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Errorf("redirected to %q after the config no longer allows it", loc)
			}
		})
	}
}

func TestCallbackNonceCookie(t *testing.T) {
	const nonce = "the-nonce-value"
	withNonce := func(n string) string {
		return sealState(t, seal.StatePayload{
			CID: nonceID, RU: nonceRU, HasST: false, IAT: fixedNow.Unix(), Nonce: n,
		})
	}

	for _, tc := range []struct {
		name     string
		state    string
		cookie   string
		hasCooki bool
		wantCode int
	}{
		{"match", withNonce(nonce), nonce, true, http.StatusFound},
		{"mismatch", withNonce(nonce), "wrong", true, http.StatusBadRequest},
		{"missing cookie", withNonce(nonce), "", false, http.StatusBadRequest},
		{"empty cookie", withNonce(nonce), "", true, http.StatusBadRequest},
		{"state without a nonce", withNonce(""), nonce, true, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, h := newTestSetup(t)
			q := url.Values{"code": {"C"}, "state": {tc.state}}
			r := httptest.NewRequest(http.MethodGet, callbackURL(q), nil)
			if tc.hasCooki {
				r.AddCookie(&http.Cookie{Name: oauth.NonceCookieName, Value: tc.cookie})
			}
			rec := do(h, r)

			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantCode)
			}
			// The nonce is single-use: the cookie is cleared either way.
			cleared := false
			for _, c := range rec.Result().Cookies() {
				if c.Name == oauth.NonceCookieName && c.MaxAge < 0 {
					cleared = true
				}
			}
			if !cleared {
				t.Error("nonce cookie was not cleared")
			}
		})
	}
}

// flipChar returns a different character in the base64url alphabet.
func flipChar(c byte) string {
	if c == 'A' {
		return "B"
	}
	return "A"
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
