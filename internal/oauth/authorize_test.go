package oauth_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glandais/strava-auth-proxy/internal/oauth"
	"github.com/glandais/strava-auth-proxy/internal/seal"
)

// openState opens a packed state token minted by the authorize handler.
func openState(t *testing.T, token string) seal.StatePayload {
	t.Helper()
	var p seal.StatePayload
	if err := testRing.Open(seal.DomainState, token, &p, 15*time.Minute, fixedNow); err != nil {
		t.Fatalf("opening sealed state: %v", err)
	}
	return p
}

func TestAuthorizeRedirectsToStrava(t *testing.T) {
	for _, tc := range []struct {
		name     string
		path     string
		wantPath string
	}{
		{"web", "/oauth/authorize", "/oauth/authorize"},
		{"mobile", "/oauth/mobile/authorize", "/oauth/mobile/authorize"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, h := newTestSetup(t)

			q := url.Values{
				"client_id":       {virtualID},
				"redirect_uri":    {virtualRU},
				"response_type":   {"code"},
				"scope":           {"read,activity:read_all"},
				"approval_prompt": {"force"},
				"state":           {"abc 123/+&"},
				"unknown_param":   {"kept"},
			}
			rec := do(h, httptest.NewRequest(http.MethodGet, tc.path+"?"+q.Encode(), nil))
			loc := location(t, rec)
			assertNoSecret(t, rec)

			if loc.Path != tc.wantPath {
				t.Errorf("upstream path = %q, want %q", loc.Path, tc.wantPath)
			}
			got := loc.Query()
			if got.Get("client_id") != realClientID {
				t.Errorf("client_id = %q, want the real one %q", got.Get("client_id"), realClientID)
			}
			if got.Get("redirect_uri") != "https://proxy.example/oauth/callback" {
				t.Errorf("redirect_uri = %q, want the proxy callback", got.Get("redirect_uri"))
			}
			// Everything the proxy does not own is forwarded verbatim.
			for k, want := range map[string]string{
				"response_type":   "code",
				"scope":           "read,activity:read_all",
				"approval_prompt": "force",
				"unknown_param":   "kept",
			} {
				if got.Get(k) != want {
					t.Errorf("%s = %q, want %q", k, got.Get(k), want)
				}
			}
			// The caller's own state never reaches Strava in the clear.
			if got.Get("state") == "abc 123/+&" {
				t.Error("caller state forwarded unsealed")
			}
			st := openState(t, got.Get("state"))
			if st.CID != virtualID || st.RU != virtualRU || st.ST != "abc 123/+&" || !st.HasST {
				t.Errorf("sealed state = %+v", st)
			}
			if st.IAT != fixedNow.Unix() {
				t.Errorf("iat = %d, want %d", st.IAT, fixedNow.Unix())
			}
			if st.Nonce != "" {
				t.Errorf("nonce = %q, want empty for a client that did not opt in", st.Nonce)
			}
			if cookies := rec.Result().Cookies(); len(cookies) != 0 {
				t.Errorf("unexpected cookies: %v", cookies)
			}
		})
	}
}

func TestAuthorizeStatePresence(t *testing.T) {
	for _, tc := range []struct {
		name      string
		state     []string
		wantHasST bool
		wantST    string
	}{
		{"absent", nil, false, ""},
		{"empty", []string{""}, true, ""},
		{"set", []string{"xyz"}, true, "xyz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, h := newTestSetup(t)
			q := url.Values{"client_id": {virtualID}, "redirect_uri": {virtualRU}}
			if tc.state != nil {
				q["state"] = tc.state
			}
			rec := do(h, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
			st := openState(t, location(t, rec).Query().Get("state"))
			if st.HasST != tc.wantHasST || st.ST != tc.wantST {
				t.Errorf("HasST=%v ST=%q, want %v %q", st.HasST, st.ST, tc.wantHasST, tc.wantST)
			}
		})
	}
}

func TestAuthorizeRejections(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query url.Values
	}{
		{"unknown client_id", url.Values{"client_id": {"99999"}, "redirect_uri": {virtualRU}}},
		{"missing client_id", url.Values{"redirect_uri": {virtualRU}}},
		{"missing redirect_uri", url.Values{"client_id": {virtualID}}},
		{"redirect_uri of another client", url.Values{"client_id": {virtualID}, "redirect_uri": {otherRU}}},
		{"redirect_uri suffix attack", url.Values{"client_id": {virtualID}, "redirect_uri": {virtualRU + "/evil"}}},
		{"redirect_uri host attack", url.Values{"client_id": {virtualID}, "redirect_uri": {"https://app.example.evil/cb"}}},
		{"redirect_uri trailing slash", url.Values{"client_id": {virtualID}, "redirect_uri": {virtualRU + "/"}}},
		{"redirect_uri case change", url.Values{"client_id": {virtualID}, "redirect_uri": {"https://APP.example/cb"}}},
		{"oversized state", url.Values{
			"client_id":    {virtualID},
			"redirect_uri": {virtualRU},
			"state":        {strings.Repeat("s", oauth.MaxCallerStateLen+1)},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, _, h := newTestSetup(t)
			rec := do(h, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+tc.query.Encode(), nil))

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Errorf("error path redirected to %q; it must never redirect", loc)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Errorf("Content-Type = %q, want an HTML page", ct)
			}
			if fake.count() != 0 {
				t.Errorf("upstream contacted %d times on a rejected request", fake.count())
			}
			assertNoSecret(t, rec)
		})
	}
}

// A state of exactly the cap is accepted; only what exceeds it is refused.
func TestAuthorizeStateAtCapAccepted(t *testing.T) {
	_, _, h := newTestSetup(t)
	q := url.Values{
		"client_id":    {virtualID},
		"redirect_uri": {virtualRU},
		"state":        {strings.Repeat("s", oauth.MaxCallerStateLen)},
	}
	rec := do(h, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
}

// Strange scope and response_type values are Strava's business, not the
// proxy's: they must reach Strava and never produce a proxy-minted 400.
func TestAuthorizePassesThroughInvalidLookingParams(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra url.Values
	}{
		{"no scope", url.Values{}},
		{"response_type=token", url.Values{"response_type": {"token"}}},
		{"unknown scope", url.Values{"scope": {"not-a-real-scope"}}},
		{"space delimited scope", url.Values{"scope": {"read activity:read_all"}}},
		{"garbage approval_prompt", url.Values{"approval_prompt": {"maybe"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, h := newTestSetup(t)
			q := url.Values{"client_id": {virtualID}, "redirect_uri": {virtualRU}}
			for k, vs := range tc.extra {
				q[k] = vs
			}
			rec := do(h, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
			got := location(t, rec).Query()
			for k, vs := range tc.extra {
				if got.Get(k) != vs[0] {
					t.Errorf("%s = %q, want %q forwarded verbatim", k, got.Get(k), vs[0])
				}
			}
		})
	}
}

func TestAuthorizeSetsNonceCookieWhenRequired(t *testing.T) {
	_, _, h := newTestSetup(t)
	q := url.Values{"client_id": {nonceID}, "redirect_uri": {nonceRU}}
	rec := do(h, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))

	st := openState(t, location(t, rec).Query().Get("state"))
	if st.Nonce == "" {
		t.Fatal("nonce not bound into the sealed state")
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	c := cookies[0]
	if c.Name != oauth.NonceCookieName {
		t.Errorf("cookie name = %q, want %q", c.Name, oauth.NonceCookieName)
	}
	if c.Value != st.Nonce {
		t.Error("cookie value does not match the nonce sealed into the state")
	}
	if !c.Secure || !c.HttpOnly || c.Path != "/" || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie attributes = %+v, want Secure HttpOnly Path=/ SameSite=Lax", c)
	}
	if c.MaxAge <= 0 {
		t.Errorf("cookie MaxAge = %d, want the state TTL", c.MaxAge)
	}
	// Two flows must never share a nonce.
	rec2 := do(h, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	st2 := openState(t, location(t, rec2).Query().Get("state"))
	if st2.Nonce == st.Nonce {
		t.Error("nonce reused across authorizations")
	}
}
