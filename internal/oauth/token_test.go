package oauth_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glandais/strava-auth-proxy/internal/config"
	"github.com/glandais/strava-auth-proxy/internal/seal"
)

// Golden Fault bodies, byte-for-byte as internal/fault writes them.
const (
	goldenInvalidClientID     = `{"message":"Bad Request","errors":[{"resource":"Application","field":"client_id","code":"invalid"}]}`
	goldenInvalidClientSecret = `{"message":"Bad Request","errors":[{"resource":"Application","field":"client_secret","code":"invalid"}]}`
	goldenInvalidCode         = `{"message":"Bad Request","errors":[{"resource":"AuthorizationCode","field":"code","code":"invalid"}]}`
	goldenUnauthorized        = `{"message":"Authorization Error","errors":[{"resource":"Application","field":"client_id","code":"invalid"}]}`
	goldenUnavailable         = `{"message":"Bad Gateway","errors":[{"resource":"Upstream","field":"strava","code":"unavailable"}]}`
	goldenTimeout             = `{"message":"Gateway Timeout","errors":[{"resource":"Upstream","field":"strava","code":"timeout"}]}`
)

// tokenRoutes are the two paths that must behave identically.
var tokenRoutes = []string{"/oauth/token", "/api/v3/oauth/token"}

// wrappedCode returns a wrapped code minted for cid.
func wrappedCode(t *testing.T, cid, raw string) string {
	t.Helper()
	return sealCode(t, seal.CodePayload{CID: cid, SC: raw, IAT: fixedNow.Unix()})
}

func assertGolden(t *testing.T, rec *httptest.ResponseRecorder, status int, body string) {
	t.Helper()
	if rec.Code != status {
		t.Errorf("status = %d, want %d", rec.Code, status)
	}
	if got := rec.Body.String(); got != body {
		t.Errorf("body =\n  %s\nwant\n  %s", got, body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	assertNoSecret(t, rec)
}

func TestTokenAuthorizationCodeExchange(t *testing.T) {
	for _, route := range tokenRoutes {
		t.Run(route, func(t *testing.T) {
			fake, _, h := newTestSetup(t)
			const upstreamBody = `{"token_type":"Bearer","expires_at":1568775134,"expires_in":21600,` +
				`"refresh_token":"e5n5","access_token":"a4b9","athlete":{"id":1,"username":"undocumented"}}`
			fake.respond = func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(upstreamBody))
			}

			form := url.Values{
				"client_id":     {virtualID},
				"client_secret": {virtualSecret},
				"code":          {wrappedCode(t, virtualID, "RAW-CODE")},
				"grant_type":    {"authorization_code"},
				"extra_param":   {"kept"},
			}
			rec := do(h, postForm(route, form))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
			}
			if got := rec.Body.String(); got != upstreamBody {
				t.Errorf("body was not relayed verbatim:\n got %s\nwant %s", got, upstreamBody)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
				t.Errorf("Content-Type = %q, want the upstream value", ct)
			}
			assertNoSecret(t, rec)

			if n := fake.count(); n != 1 {
				t.Fatalf("upstream attempts = %d, want exactly 1 (codes are single-use)", n)
			}
			up := fake.last(t)
			if up.Path != "/api/v3/oauth/token" {
				t.Errorf("upstream path = %q", up.Path)
			}
			if up.Form.Get("client_id") != realClientID {
				t.Errorf("upstream client_id = %q, want the real one", up.Form.Get("client_id"))
			}
			if up.Form.Get("client_secret") != realClientSecret {
				t.Error("real client_secret not substituted upstream")
			}
			if up.Form.Get("code") != "RAW-CODE" {
				t.Errorf("upstream code = %q, want the unwrapped raw code", up.Form.Get("code"))
			}
			if up.Form.Get("grant_type") != "authorization_code" {
				t.Errorf("upstream grant_type = %q", up.Form.Get("grant_type"))
			}
			if up.Form.Get("extra_param") != "kept" {
				t.Error("unknown parameter not forwarded verbatim")
			}
		})
	}
}

func TestTokenRefreshGrant(t *testing.T) {
	fake, _, h := newTestSetup(t)
	form := url.Values{
		"client_id":     {virtualID},
		"client_secret": {virtualSecret},
		"grant_type":    {"refresh_token"},
		"refresh_token": {"REFRESH-TOKEN"},
	}
	rec := do(h, postForm("/oauth/token", form))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	up := fake.last(t)
	if up.Form.Get("refresh_token") != "REFRESH-TOKEN" {
		t.Errorf("refresh_token = %q, want it forwarded untouched", up.Form.Get("refresh_token"))
	}
	if up.Form.Get("client_secret") != realClientSecret || up.Form.Get("client_id") != realClientID {
		t.Error("real credentials not substituted on the refresh leg")
	}
	if _, ok := up.Form["code"]; ok {
		t.Error("a code parameter was invented on the refresh leg")
	}
	assertNoSecret(t, rec)
}

// Strava accepts token parameters in the query string as well as the body, and
// so must the proxy.
func TestTokenAcceptsCredentialsAnywhere(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query url.Values
		form  url.Values
	}{
		{
			name:  "all in query",
			query: url.Values{"client_id": {virtualID}, "client_secret": {virtualSecret}, "grant_type": {"refresh_token"}, "refresh_token": {"R"}},
		},
		{
			name: "all in body",
			form: url.Values{"client_id": {virtualID}, "client_secret": {virtualSecret}, "grant_type": {"refresh_token"}, "refresh_token": {"R"}},
		},
		{
			name:  "split across both",
			query: url.Values{"client_id": {virtualID}, "grant_type": {"refresh_token"}},
			form:  url.Values{"client_secret": {virtualSecret}, "refresh_token": {"R"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, _, h := newTestSetup(t)
			path := "/oauth/token"
			if len(tc.query) > 0 {
				path += "?" + tc.query.Encode()
			}
			rec := do(h, postForm(path, tc.form))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
			}
			if up := fake.last(t); up.Form.Get("refresh_token") != "R" {
				t.Errorf("refresh_token = %q", up.Form.Get("refresh_token"))
			}
		})
	}
}

func TestTokenProxyMintedFaults(t *testing.T) {
	expiredCode := sealCode(t, seal.CodePayload{
		CID: virtualID, SC: "RAW", IAT: fixedNow.Add(-16 * time.Minute).Unix(),
	})
	stateAsCode := sealState(t, seal.StatePayload{CID: virtualID, RU: virtualRU, IAT: fixedNow.Unix()})

	for _, tc := range []struct {
		name string
		form func(t *testing.T) url.Values
		body string
	}{
		{
			name: "unknown client_id",
			form: func(*testing.T) url.Values {
				return url.Values{"client_id": {"99999"}, "client_secret": {virtualSecret}, "grant_type": {"refresh_token"}}
			},
			body: goldenInvalidClientID,
		},
		{
			name: "missing client_id",
			form: func(*testing.T) url.Values { return url.Values{"grant_type": {"refresh_token"}} },
			body: goldenInvalidClientID,
		},
		{
			name: "wrong client_secret",
			form: func(*testing.T) url.Values {
				return url.Values{"client_id": {virtualID}, "client_secret": {"nope"}, "grant_type": {"refresh_token"}}
			},
			body: goldenInvalidClientSecret,
		},
		{
			name: "missing client_secret",
			form: func(*testing.T) url.Values {
				return url.Values{"client_id": {virtualID}, "grant_type": {"refresh_token"}}
			},
			body: goldenInvalidClientSecret,
		},
		{
			name: "another client's secret",
			form: func(*testing.T) url.Values {
				return url.Values{"client_id": {virtualID}, "client_secret": {otherSecret}, "grant_type": {"refresh_token"}}
			},
			body: goldenInvalidClientSecret,
		},
		{
			name: "malformed code",
			form: func(*testing.T) url.Values {
				return url.Values{"client_id": {virtualID}, "client_secret": {virtualSecret},
					"grant_type": {"authorization_code"}, "code": {"garbage"}}
			},
			body: goldenInvalidCode,
		},
		{
			name: "missing code",
			form: func(*testing.T) url.Values {
				return url.Values{"client_id": {virtualID}, "client_secret": {virtualSecret},
					"grant_type": {"authorization_code"}}
			},
			body: goldenInvalidCode,
		},
		{
			name: "expired code",
			form: func(*testing.T) url.Values {
				return url.Values{"client_id": {virtualID}, "client_secret": {virtualSecret},
					"grant_type": {"authorization_code"}, "code": {expiredCode}}
			},
			body: goldenInvalidCode,
		},
		{
			name: "state envelope presented as a code",
			form: func(*testing.T) url.Values {
				return url.Values{"client_id": {virtualID}, "client_secret": {virtualSecret},
					"grant_type": {"authorization_code"}, "code": {stateAsCode}}
			},
			body: goldenInvalidCode,
		},
		{
			name: "code minted for another client",
			form: func(t *testing.T) url.Values {
				return url.Values{"client_id": {otherID}, "client_secret": {otherSecret},
					"grant_type": {"authorization_code"}, "code": {wrappedCode(t, virtualID, "RAW")}}
			},
			body: goldenInvalidCode,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, _, h := newTestSetup(t)
			rec := do(h, postForm("/oauth/token", tc.form(t)))
			assertGolden(t, rec, http.StatusBadRequest, tc.body)
			if fake.count() != 0 {
				t.Errorf("upstream contacted %d times on a locally rejected exchange", fake.count())
			}
		})
	}
}

// An unknown or missing grant_type is Strava's error to mint, not the proxy's.
func TestTokenForwardsUnknownGrantTypes(t *testing.T) {
	for _, grant := range []string{"", "client_credentials", "made_up"} {
		t.Run("grant="+grant, func(t *testing.T) {
			fake, _, h := newTestSetup(t)
			const stravaBody = `{"message":"Bad Request","errors":[{"resource":"Application","field":"grant_type","code":"invalid"}]}`
			fake.respond = func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(stravaBody))
			}
			form := url.Values{"client_id": {virtualID}, "client_secret": {virtualSecret}}
			if grant != "" {
				form.Set("grant_type", grant)
			}
			rec := do(h, postForm("/oauth/token", form))

			if fake.count() != 1 {
				t.Fatalf("upstream attempts = %d, want 1: the proxy must not mint a grant_type fault", fake.count())
			}
			if got := fake.last(t).Form.Get("grant_type"); got != grant {
				t.Errorf("upstream grant_type = %q, want %q verbatim", got, grant)
			}
			if rec.Code != http.StatusBadRequest || rec.Body.String() != stravaBody {
				t.Errorf("Strava's error was not relayed verbatim: %d %s", rec.Code, rec.Body.String())
			}
			assertNoSecret(t, rec)
		})
	}
}

// Whatever Strava answers is relayed byte-for-byte, including statuses and
// bodies the proxy knows nothing about.
func TestTokenRelaysUpstreamResponsesVerbatim(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
	}{
		{http.StatusBadRequest, `{"message":"Bad Request","errors":[{"resource":"AuthorizationCode","field":"code","code":"invalid"}]}`},
		{http.StatusUnauthorized, `{"message":"Authorization Error","errors":[]}`},
		{http.StatusTooManyRequests, `{"message":"Rate Limit Exceeded","errors":[{"resource":"Application","field":"rate limit","code":"exceeded"}]}`},
		{http.StatusInternalServerError, "not even json"},
		{http.StatusOK, ""},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			fake, _, h := newTestSetup(t)
			fake.respond = func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}
			form := url.Values{"client_id": {virtualID}, "client_secret": {virtualSecret},
				"grant_type": {"refresh_token"}, "refresh_token": {"R"}}
			rec := do(h, postForm("/oauth/token", form))

			if rec.Code != tc.status {
				t.Errorf("status = %d, want %d", rec.Code, tc.status)
			}
			if rec.Body.String() != tc.body {
				t.Errorf("body = %q, want %q", rec.Body.String(), tc.body)
			}
			if fake.count() != 1 {
				t.Errorf("upstream attempts = %d, want exactly 1 (no retries)", fake.count())
			}
			assertNoSecret(t, rec)
		})
	}
}

func TestTokenUpstreamUnavailable(t *testing.T) {
	// A server that is closed before the request: connection refused.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	base := dead.URL
	dead.Close()

	cfg := testConfig(base)
	mux := http.NewServeMux()
	newHandler(config.NewHolder(cfg)).Register(mux)

	form := url.Values{"client_id": {virtualID}, "client_secret": {virtualSecret},
		"grant_type": {"refresh_token"}, "refresh_token": {"R"}}
	rec := do(mux, postForm("/oauth/token", form))
	assertGolden(t, rec, http.StatusBadGateway, goldenUnavailable)
}

func TestTokenUpstreamTimeout(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	t.Cleanup(slow.Close)

	h := newHandler(config.NewHolder(testConfig(slow.URL)))
	h.Client = &http.Client{Timeout: 20 * time.Millisecond}
	mux := http.NewServeMux()
	h.Register(mux)

	form := url.Values{"client_id": {virtualID}, "client_secret": {virtualSecret},
		"grant_type": {"refresh_token"}, "refresh_token": {"R"}}
	rec := do(mux, postForm("/oauth/token", form))
	assertGolden(t, rec, http.StatusGatewayTimeout, goldenTimeout)
}

// The exact "/api/v3/oauth/token" pattern must win over an "/api/v3/"
// catch-all, which is how main.go mounts the reverse proxy.
func TestTokenRouteBeatsAPICatchAll(t *testing.T) {
	fake, holder, _ := newTestSetup(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	newHandler(holder).Register(mux)

	form := url.Values{"client_id": {virtualID}, "client_secret": {virtualSecret},
		"grant_type": {"refresh_token"}, "refresh_token": {"R"}}
	rec := do(mux, postForm("/api/v3/oauth/token", form))
	if rec.Code == http.StatusTeapot {
		t.Fatal("the /api/v3/ catch-all swallowed the token endpoint")
	}
	if fake.count() != 1 {
		t.Errorf("upstream attempts = %d, want 1", fake.count())
	}
}

// The body the proxy sends upstream is form-encoded and self-consistent.
func TestTokenUpstreamRequestShape(t *testing.T) {
	fake, _, h := newTestSetup(t)
	form := url.Values{"client_id": {virtualID}, "client_secret": {virtualSecret},
		"grant_type": {"authorization_code"}, "code": {wrappedCode(t, virtualID, "RAW")}}
	do(h, postForm("/oauth/token", form))

	up := fake.last(t)
	if up.Method != http.MethodPost {
		t.Errorf("method = %s, want POST", up.Method)
	}
	if ct := up.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		t.Errorf("upstream Content-Type = %q", ct)
	}
	if strings.Contains(up.Query.Encode(), virtualSecret) {
		t.Error("virtual secret forwarded upstream")
	}
	if strings.Contains(up.Body, virtualSecret) {
		t.Error("virtual secret forwarded upstream in the body")
	}
}
