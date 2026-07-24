package integration

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/glandais/strava-auth-proxy/internal/fakestrava"
	"github.com/glandais/strava-auth-proxy/internal/httpmid"
)

// TestSecretLeakSweep is the explicit form of the sweep every harness in this
// package runs on cleanup (DESIGN.md §6).
//
// It drives a wide mix of successful and failing requests through one proxy,
// then asserts three things: that the capture is not vacuous, that the real
// Strava application secret genuinely travels upstream (so the sentinel is
// actually in play), and that it appears in no response and no log record.
func TestSecretLeakSweep(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.Fake.SetAthleteJSON([]byte(athleteJSON))

	const callerState = "sweep-state-☃"

	// --- browser leg, success and every failure mode ------------------------
	q := authorizeQuery()
	q.Set("state", callerState)
	wrapped := h.wrappedCode(q)

	h.get(h.URL + "/oauth/authorize?client_id=99999&redirect_uri=" + url.QueryEscape(appRedirectURI))
	h.get(h.URL + "/oauth/authorize?client_id=" + clientAID + "&redirect_uri=" + url.QueryEscape("https://evil.example/cb"))
	h.get(h.URL + "/oauth/callback?state=forged&code=C")
	h.get(h.URL + "/oauth/mobile/authorize?" + q.Encode())

	// --- token leg ----------------------------------------------------------
	res := h.exchange(clientAID, clientASecret, wrapped)
	assertStatus(t, res, http.StatusOK)
	tok := decodeToken(t, res)

	h.exchange(clientAID, clientASecret, wrapped)         // replayed: Strava fault
	h.exchange(clientAID, "wrong-secret", wrapped)        // proxy fault
	h.exchange("99999", clientASecret, wrapped)           // proxy fault
	h.exchange(clientBID, clientBSecret, wrapped)         // cross-client theft
	h.refresh(clientAID, clientASecret, tok.RefreshToken) // success
	h.refresh(clientAID, clientASecret, "not-a-token")    // Strava fault

	// Credentials in the query string, the other shape Strava accepts: the
	// access log must redact it just the same.
	h.postForm(h.URL+"/oauth/token?client_id="+clientAID+"&client_secret="+url.QueryEscape(clientASecret),
		url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}})

	// --- deauthorize / revoke ----------------------------------------------
	h.postForm(h.URL+"/oauth/deauthorize", url.Values{"access_token": {tok.AccessToken}})
	h.postForm(h.URL+"/oauth/revoke", url.Values{"token": {tok.RefreshToken}},
		func(r *http.Request) { r.SetBasicAuth(clientAID, clientASecret) })
	h.postForm(h.URL+"/oauth/revoke", url.Values{"token": {tok.RefreshToken}},
		func(r *http.Request) { r.SetBasicAuth(clientAID, "wrong-secret") })

	// --- reverse proxy ------------------------------------------------------
	h.get(h.URL+"/api/v3/athlete", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	})
	h.get(h.URL + fakestrava.PathRateLimited)
	h.get(h.URL + fakestrava.PathUnauthorized)

	// --- the sweep is not vacuous ------------------------------------------
	captured := h.rec.snapshot()
	if len(captured) < 20 {
		t.Fatalf("only %d responses captured; the sweep would prove little", len(captured))
	}
	logs := h.logs.String()
	if !strings.Contains(logs, "http request") {
		t.Fatal("no access-log records captured; the log sweep would prove nothing")
	}

	// The real secret really is in flight: the fake received it upstream.
	var sawRealSecret bool
	for _, r := range h.Fake.Requests() {
		if r.Form.Get("client_secret") == realClientSecret {
			sawRealSecret = true
			break
		}
	}
	if !sawRealSecret {
		t.Fatal("the real client secret never reached the fake; the sentinel is not in play")
	}

	// --- the sweep itself ---------------------------------------------------
	h.assertNoSecretLeak()

	// Specific tokens, not just the fake's prefixes.
	for name, value := range map[string]string{
		"access token":  tok.AccessToken,
		"refresh token": tok.RefreshToken,
	} {
		if strings.Contains(logs, value) {
			t.Errorf("a raw %s appears in a log record", name)
		}
	}

	// The access log redacts query strings wholesale, so neither the wrapped
	// code nor the caller's state can reach the log through a URL.
	if !strings.Contains(logs, httpmid.RedactedQuery) {
		t.Errorf("no redacted-query marker in the log; query redaction is not being exercised")
	}
	for name, value := range map[string]string{
		"wrapped authorization code": wrapped,
		"caller state":               callerState,
	} {
		if strings.Contains(logs, value) {
			t.Errorf("the %s appears in a log record", name)
		}
	}
}

// TestErrorPagesNeverEchoTheRequest covers the reason fault.WriteBadRequestPage
// takes a static detail string: a page that reflected the query would put an
// authorization code into the browser's history, a screenshot or a paste.
func TestErrorPagesNeverEchoTheRequest(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	const marker = "REFLECTED-MARKER-8821"
	responses := []*result{
		h.get(h.URL + "/oauth/authorize?client_id=99999&redirect_uri=" + url.QueryEscape("https://x.example/"+marker)),
		h.get(h.URL + "/oauth/authorize?client_id=" + clientAID + "&redirect_uri=" + url.QueryEscape("https://evil.example/"+marker)),
		h.get(h.URL + "/oauth/callback?state=" + marker + "&code=" + marker),
	}
	for i, res := range responses {
		assertNoRedirect(t, res)
		if strings.Contains(string(res.Body), marker) {
			t.Errorf("response %d reflected the request back to the browser", i)
		}
	}
}
