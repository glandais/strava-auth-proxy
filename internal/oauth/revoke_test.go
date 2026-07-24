package oauth_test

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestDeauthorizeIsPurePassThrough(t *testing.T) {
	fake, _, h := newTestSetup(t)
	fake.respond = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"a4b9"}`))
	}

	form := url.Values{"access_token": {"ATHLETE-ACCESS-TOKEN"}}
	req := postForm("/oauth/deauthorize", form)
	req.Header.Set("Authorization", "Bearer ATHLETE-ACCESS-TOKEN")
	rec := do(h, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != `{"access_token":"a4b9"}` {
		t.Errorf("body = %q, want the upstream body verbatim", rec.Body.String())
	}
	assertNoSecret(t, rec)

	up := fake.last(t)
	if up.Path != "/oauth/deauthorize" {
		t.Errorf("upstream path = %q", up.Path)
	}
	if up.Form.Get("access_token") != "ATHLETE-ACCESS-TOKEN" {
		t.Errorf("body not forwarded verbatim: %q", up.Body)
	}
	if up.Header.Get("Authorization") != "Bearer ATHLETE-ACCESS-TOKEN" {
		t.Errorf("Authorization = %q, want the athlete's Bearer untouched", up.Header.Get("Authorization"))
	}
	// The legacy endpoint authenticates with the token alone: no client
	// credentials of any kind belong on this leg.
	if strings.Contains(up.Body, realClientSecret) || strings.Contains(up.Header.Get("Authorization"), realClientSecret) {
		t.Error("real Strava credentials leaked onto the deauthorize leg")
	}
}

func TestDeauthorizeRelaysErrorsVerbatim(t *testing.T) {
	fake, _, h := newTestSetup(t)
	const body = `{"message":"Authorization Error","errors":[{"resource":"Athlete","field":"access_token","code":"invalid"}]}`
	fake.respond = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(body))
	}
	rec := do(h, postForm("/oauth/deauthorize", url.Values{"access_token": {"bad"}}))
	if rec.Code != http.StatusUnauthorized || rec.Body.String() != body {
		t.Errorf("got %d %q, want the upstream response verbatim", rec.Code, rec.Body.String())
	}
}

func TestRevokeSubstitutesBasicCredentials(t *testing.T) {
	fake, _, h := newTestSetup(t)
	fake.respond = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // 200, empty body — RFC 7009 semantics
	}

	form := url.Values{"token": {"TOKEN-TO-REVOKE"}, "token_type_hint": {"refresh_token"}}
	req := postForm("/oauth/revoke", form)
	req.SetBasicAuth(virtualID, virtualSecret)
	rec := do(h, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body = %q, want it relayed empty", rec.Body.String())
	}
	assertNoSecret(t, rec)

	up := fake.last(t)
	if up.Path != "/oauth/revoke" {
		t.Errorf("upstream path = %q", up.Path)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(realClientID+":"+realClientSecret))
	if got := up.Header.Get("Authorization"); got != want {
		t.Error("upstream Basic credentials are not the real application's")
	}
	if strings.Contains(up.Header.Get("Authorization"), virtualSecret) {
		t.Error("virtual secret forwarded upstream")
	}
	if up.Form.Get("token") != "TOKEN-TO-REVOKE" || up.Form.Get("token_type_hint") != "refresh_token" {
		t.Errorf("token fields not forwarded untouched: %q", up.Body)
	}
}

func TestRevokeRejectsBadCredentials(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(r *http.Request)
	}{
		{"no Authorization header", func(*http.Request) {}},
		{"unknown client", func(r *http.Request) { r.SetBasicAuth("99999", virtualSecret) }},
		{"wrong secret", func(r *http.Request) { r.SetBasicAuth(virtualID, "nope") }},
		{"another client's secret", func(r *http.Request) { r.SetBasicAuth(virtualID, otherSecret) }},
		{"empty secret", func(r *http.Request) { r.SetBasicAuth(virtualID, "") }},
		{"bearer instead of basic", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+virtualSecret) }},
		{"malformed basic", func(r *http.Request) { r.Header.Set("Authorization", "Basic !!!not-base64") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, _, h := newTestSetup(t)
			req := postForm("/oauth/revoke", url.Values{"token": {"T"}})
			tc.set(req)
			rec := do(h, req)

			assertGolden(t, rec, http.StatusUnauthorized, goldenUnauthorized)
			if fake.count() != 0 {
				t.Errorf("upstream contacted %d times with unauthenticated credentials", fake.count())
			}
		})
	}
}

func TestRevokeRelaysUpstreamStatuses(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
	}{
		{http.StatusBadRequest, `{"message":"Bad Request","errors":[{"resource":"Token","field":"token","code":"required"}]}`},
		{http.StatusServiceUnavailable, ""},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			fake, _, h := newTestSetup(t)
			fake.respond = func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}
			req := postForm("/oauth/revoke", url.Values{"token": {"T"}})
			req.SetBasicAuth(virtualID, virtualSecret)
			rec := do(h, req)

			if rec.Code != tc.status || rec.Body.String() != tc.body {
				t.Errorf("got %d %q, want %d %q", rec.Code, rec.Body.String(), tc.status, tc.body)
			}
			if fake.count() != 1 {
				t.Errorf("upstream attempts = %d, want exactly 1", fake.count())
			}
		})
	}
}
