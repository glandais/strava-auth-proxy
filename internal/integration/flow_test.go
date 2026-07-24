package integration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glandais/strava-auth-proxy/internal/seal"
)

// athleteJSON is the athlete object the fake returns on the authorization_code
// grant. It is already compact, so it can be compared byte-for-byte with what
// the proxy relays, and it carries a field that appears in no Strava schema —
// the proof that the relay does not re-marshal through a typed model.
const athleteJSON = `{"id":227615,"resource_state":2,"firstname":"Fake","lastname":"Athlete",` +
	`"username":"fakeathlete","sap_undocumented_extra":{"nested":[1,2,3],"weird key":"vàlue ☃"}}`

// tokenBody is the subset of a token response the tests need. The athlete is
// kept raw so the comparison stays byte-exact.
type tokenBody struct {
	TokenType    string          `json:"token_type"`
	ExpiresAt    int64           `json:"expires_at"`
	ExpiresIn    int             `json:"expires_in"`
	RefreshToken string          `json:"refresh_token"`
	AccessToken  string          `json:"access_token"`
	Athlete      json.RawMessage `json:"athlete"`
}

func decodeToken(t *testing.T, res *result) tokenBody {
	t.Helper()
	var tb tokenBody
	if err := json.Unmarshal(res.Body, &tb); err != nil {
		t.Fatalf("decoding token response: %v (body: %s)", err, res.Body)
	}
	return tb
}

// TestHappyPath walks the whole contract of DESIGN.md §1.1 in one flow:
// authorize, Strava, callback, the caller's redirect, the code exchange, a
// refresh, a deauthorization and a revocation.
func TestHappyPath(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.Fake.SetAthleteJSON([]byte(athleteJSON))

	callerState := "caller-csrf-token-1"
	q := authorizeQuery()
	q.Set("state", callerState)

	// Hop 1: caller -> proxy /oauth/authorize -> Strava.
	toStrava := h.get(h.URL + "/oauth/authorize?" + q.Encode())
	assertStatus(t, toStrava, http.StatusFound)
	assertOAuthHardening(t, toStrava)

	stravaURL := location(t, toStrava)
	if got, want := stravaURL.Path, "/oauth/authorize"; got != want {
		t.Errorf("upstream path = %q, want %q", got, want)
	}
	sq := stravaURL.Query()
	if got := sq.Get("client_id"); got != realClientID {
		t.Errorf("upstream client_id = %q, want the real application id %q", got, realClientID)
	}
	if got, want := sq.Get("redirect_uri"), h.Holder.Get().CallbackURL(); got != want {
		t.Errorf("upstream redirect_uri = %q, want %q", got, want)
	}
	// Everything the proxy does not own is forwarded verbatim.
	for _, p := range []string{"response_type", "scope", "approval_prompt"} {
		if got, want := sq.Get(p), q.Get(p); got != want {
			t.Errorf("upstream %s = %q, want %q", p, got, want)
		}
	}
	if sq.Get("state") == callerState {
		t.Error("the caller's state reached Strava unsealed")
	}
	if strings.Contains(stravaURL.String(), appRedirectURI) {
		t.Error("the caller's redirect_uri reached Strava")
	}

	// Hop 2: browser -> Strava -> proxy /oauth/callback.
	toCallback := h.follow(toStrava)
	assertStatus(t, toCallback, http.StatusFound)
	callbackURL := location(t, toCallback)
	if got, want := callbackURL.Path, "/oauth/callback"; got != want {
		t.Fatalf("Strava redirected to %q, want %q", got, want)
	}

	// Hop 3: proxy /oauth/callback -> the caller's redirect_uri.
	toApp := h.follow(toCallback)
	assertStatus(t, toApp, http.StatusFound)
	assertOAuthHardening(t, toApp)
	appURL := location(t, toApp)
	if got, want := appURL.Scheme+"://"+appURL.Host+appURL.Path, appRedirectURI; got != want {
		t.Fatalf("final redirect = %q, want %q", got, want)
	}
	aq := appURL.Query()
	if got := aq.Get("state"); got != callerState {
		t.Errorf("round-tripped state = %q, want %q", got, callerState)
	}
	if got, want := aq.Get("scope"), "read,activity:read_all"; got != want {
		t.Errorf("granted scope = %q, want %q", got, want)
	}
	wrapped := aq.Get("code")
	if wrapped == "" {
		t.Fatal("final redirect carries no code")
	}

	// Hop 4: the app backend exchanges the wrapped code.
	h.Fake.Reset()
	res := h.exchange(clientAID, clientASecret, wrapped)
	assertStatus(t, res, http.StatusOK)
	assertOAuthHardening(t, res)
	if got, want := h.Fake.TokenRequests(), 1; got != want {
		t.Errorf("upstream token requests = %d, want %d (one attempt, no retry)", got, want)
	}
	if got := res.Header.Get("Content-Length"); got != strconv.Itoa(len(res.Body)) {
		t.Errorf("Content-Length = %q but the relayed body is %d bytes", got, len(res.Body))
	}

	tok := decodeToken(t, res)
	if tok.TokenType != "Bearer" || tok.AccessToken == "" || tok.RefreshToken == "" || tok.ExpiresIn == 0 {
		t.Errorf("token response is incomplete: %+v", tok)
	}
	if string(tok.Athlete) != athleteJSON {
		t.Errorf("athlete object was not relayed byte-for-byte:\n got %s\nwant %s", tok.Athlete, athleteJSON)
	}
	if !strings.Contains(string(res.Body), `"sap_undocumented_extra"`) {
		t.Error("the undocumented athlete field did not survive the relay")
	}

	// The upstream leg carried the real credentials, and the raw Strava code —
	// never the wrapped one.
	upstreamToken := h.Fake.RequestsTo("/api/v3/oauth/token")
	if len(upstreamToken) != 1 {
		t.Fatalf("fake saw %d token requests, want 1", len(upstreamToken))
	}
	form := upstreamToken[0].Form
	if form.Get("client_id") != realClientID || form.Get("client_secret") != realClientSecret {
		t.Error("the upstream token request did not carry the real application credentials")
	}
	if form.Get("code") == wrapped {
		t.Error("the wrapped code was forwarded to Strava instead of the raw one")
	}
	if form.Get("grant_type") != "authorization_code" {
		t.Errorf("upstream grant_type = %q", form.Get("grant_type"))
	}

	// Hop 5: refresh.
	h.Fake.Reset()
	res = h.refresh(clientAID, clientASecret, tok.RefreshToken)
	assertStatus(t, res, http.StatusOK)
	if got, want := h.Fake.TokenRequests(), 1; got != want {
		t.Errorf("upstream token requests on refresh = %d, want %d", got, want)
	}
	refreshed := decodeToken(t, res)
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" {
		t.Errorf("refresh response is incomplete: %+v", refreshed)
	}
	if refreshed.AccessToken == tok.AccessToken {
		t.Error("refresh returned the same access token")
	}
	if len(refreshed.Athlete) != 0 {
		t.Errorf("refresh response must carry no athlete, got %s", refreshed.Athlete)
	}
	if got := res.Header.Get("Content-Length"); got != strconv.Itoa(len(res.Body)) {
		t.Errorf("Content-Length = %q but the relayed body is %d bytes", got, len(res.Body))
	}

	// Hop 6: deauthorize — a pure pass-through authenticated by the access
	// token alone.
	res = h.postForm(h.URL+"/oauth/deauthorize", url.Values{"access_token": {refreshed.AccessToken}})
	assertStatus(t, res, http.StatusOK)
	assertOAuthHardening(t, res)
	var deauth struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(res.Body, &deauth); err != nil {
		t.Fatalf("decoding deauthorize response: %v (body %s)", err, res.Body)
	}
	if deauth.AccessToken != refreshed.AccessToken {
		t.Error("deauthorize did not relay the athlete's access token verbatim")
	}

	// Hop 7: revoke — virtual Basic credentials in, real Basic credentials out.
	res = h.postForm(h.URL+"/oauth/revoke", url.Values{"token": {refreshed.RefreshToken}},
		func(r *http.Request) { r.SetBasicAuth(clientAID, clientASecret) })
	assertStatus(t, res, http.StatusOK)
	revokeReqs := h.Fake.RequestsTo("/oauth/revoke")
	if len(revokeReqs) != 1 {
		t.Fatalf("fake saw %d revoke requests, want 1", len(revokeReqs))
	}
	if id, secret, ok := basicAuthOf(revokeReqs[0].Header.Get("Authorization")); !ok || id != realClientID || secret != realClientSecret {
		t.Error("the upstream revoke request did not carry the real application credentials")
	}
}

// basicAuthOf decodes an Authorization: Basic header. It is a copy of
// http.Request.BasicAuth's parsing, usable on a recorded header value.
func basicAuthOf(header string) (id, secret string, ok bool) {
	r := &http.Request{Header: http.Header{"Authorization": {header}}}
	return r.BasicAuth()
}

// TestCallerStateRoundTrip covers DESIGN.md §2.1: the caller's state is carried
// bit-exact, and omitted entirely when the caller sent none.
func TestCallerStateRoundTrip(t *testing.T) {
	t.Parallel()

	const hostile = "a b&c=d?e#f/g+h%20i\"j'k<l>m|n\\oé☃=="

	tests := []struct {
		name      string
		state     string
		sendState bool
	}{
		{name: "url hostile", state: hostile, sendState: true},
		{name: "empty but present", state: "", sendState: true},
		{name: "absent", sendState: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)

			q := authorizeQuery()
			if tc.sendState {
				q.Set("state", tc.state)
			}
			final := h.browserFlow(q)
			assertStatus(t, final, http.StatusFound)
			got := location(t, final).Query()

			values, present := got["state"]
			if !tc.sendState {
				if present {
					t.Fatalf("caller sent no state but the final redirect carries state=%q", values)
				}
				return
			}
			if !present {
				t.Fatal("caller sent a state but the final redirect carries none")
			}
			if len(values) != 1 || values[0] != tc.state {
				t.Errorf("state = %q, want %q", values, tc.state)
			}
		})
	}
}

// TestGrantedScopeSubsetRoundTrips covers DESIGN.md §2.2: Strava's word on what
// the user actually approved reaches the caller unchanged, and a callback with
// no scope produces a redirect with no scope.
func TestGrantedScopeSubsetRoundTrips(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		requested string
		granted   string
	}{
		{name: "subset", requested: "read,activity:read_all,profile:read_all", granted: "read,activity:read"},
		{name: "single", requested: "read,activity:read_all", granted: "read"},
		{name: "unknown scope echoed", requested: "read", granted: "read,some:future:scope"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			h.Fake.SetGrantedScope(tc.granted)

			q := authorizeQuery()
			q.Set("scope", tc.requested)
			q.Set("state", "s")

			final := h.browserFlow(q)
			assertStatus(t, final, http.StatusFound)
			if got := location(t, final).Query().Get("scope"); got != tc.granted {
				t.Errorf("granted scope = %q, want %q", got, tc.granted)
			}
		})
	}
}

// TestStravaDenialForwardedVerbatim covers DESIGN.md §2.2: whatever error value
// Strava sends is forwarded unchanged. Nothing is normalised to access_denied.
func TestStravaDenialForwardedVerbatim(t *testing.T) {
	t.Parallel()

	tests := []string{
		"access_denied",
		"quantum_disapproval_7",
		"Strange Value With Spaces & Symbols",
	}
	for _, errValue := range tests {
		t.Run(errValue, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			h.Fake.SetAuthorizeError(errValue)

			q := authorizeQuery()
			q.Set("state", "denial-state")

			final := h.browserFlow(q)
			assertStatus(t, final, http.StatusFound)
			assertOAuthHardening(t, final)

			got := location(t, final).Query()
			if got.Get("error") != errValue {
				t.Errorf("error = %q, want %q", got.Get("error"), errValue)
			}
			if got.Get("state") != "denial-state" {
				t.Errorf("state = %q, want the caller's own", got.Get("state"))
			}
			if _, ok := got["code"]; ok {
				t.Error("a denial must not carry a code")
			}
		})
	}
}

// TestCallbackRejectsBadState covers DESIGN.md §2.2 and §5: the callback acts
// only on a MAC-valid, unexpired, correctly domain-separated state, and every
// failure renders a page instead of redirecting.
func TestCallbackRejectsBadState(t *testing.T) {
	t.Parallel()

	h := newHarness(t, withStateTTL(15*time.Minute))
	now := time.Now()

	valid, err := h.Ring.Seal(seal.DomainState, seal.StatePayload{
		CID: clientAID, RU: appRedirectURI, ST: "s", HasST: true, IAT: now.Unix(),
	})
	if err != nil {
		t.Fatalf("sealing a valid state: %v", err)
	}
	parts := strings.Split(valid, ".")
	if len(parts) != 3 {
		t.Fatalf("sealed state has %d parts, want 3", len(parts))
	}

	expired, err := h.Ring.Seal(seal.DomainState, seal.StatePayload{
		CID: clientAID, RU: appRedirectURI, IAT: now.Add(-30 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("sealing an expired state: %v", err)
	}
	future, err := h.Ring.Seal(seal.DomainState, seal.StatePayload{
		CID: clientAID, RU: appRedirectURI, IAT: now.Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("sealing a future state: %v", err)
	}
	// A wrapped code presented where a state belongs: domain separation must
	// reject it cryptographically, before any payload is parsed.
	crossDomain, err := h.Ring.Seal(seal.DomainCode, seal.CodePayload{
		CID: clientAID, SC: "rawcode", IAT: now.Unix(),
	})
	if err != nil {
		t.Fatalf("sealing a cross-domain token: %v", err)
	}

	tests := []struct {
		name     string
		state    string
		omit     bool
		hasState bool
	}{
		{name: "missing", omit: true},
		{name: "empty", state: ""},
		{name: "not an envelope", state: "not-a-token"},
		{name: "unknown kid", state: "zz." + parts[1] + "." + parts[2]},
		{name: "tampered payload", state: parts[0] + "." + mutateB64(t, parts[1]) + "." + parts[2]},
		{name: "tampered mac", state: parts[0] + "." + parts[1] + "." + mutateB64(t, parts[2])},
		{name: "expired", state: expired},
		{name: "future dated", state: future},
		{name: "cross domain code as state", state: crossDomain},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			q := url.Values{"code": {"C-from-strava"}, "scope": {"read"}}
			if !tc.omit {
				q.Set("state", tc.state)
			}
			res := h.get(h.URL + "/oauth/callback?" + q.Encode())
			assertNoRedirect(t, res)
			assertOAuthHardening(t, res)
			// The page must never echo the request back at the browser.
			if strings.Contains(string(res.Body), "C-from-strava") {
				t.Error("the 400 page echoed the authorization code")
			}
		})
	}
}

// mutateB64 returns s with its FIRST base64url character changed.
//
// The first character always carries six significant bits, so the decoded bytes
// always differ. Mutating the last character would not be safe: in an unpadded
// encoding its low bits can be discarded, so roughly one attempt in twenty
// would decode to exactly the same bytes and the "tampered" token would verify.
// The decode-and-compare below turns that reasoning into an assertion.
func mutateB64(t *testing.T, s string) string {
	t.Helper()
	if s == "" {
		t.Fatal("cannot mutate an empty base64 string")
	}
	replacement := byte('A')
	if s[0] == 'A' {
		replacement = 'B'
	}
	mutated := string(replacement) + s[1:]

	before, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding %q: %v", s, err)
	}
	after, err := base64.RawURLEncoding.DecodeString(mutated)
	if err != nil {
		t.Fatalf("decoding the mutated value: %v", err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("the mutation did not change the decoded bytes")
	}
	return mutated
}

// TestCallbackRejectsMissingCodeAndError covers the "neither code nor error"
// branch: Strava sent nothing actionable, so there is nothing to redirect with.
func TestCallbackRejectsMissingCodeAndError(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	state, err := h.Ring.Seal(seal.DomainState, seal.StatePayload{
		CID: clientAID, RU: appRedirectURI, IAT: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("sealing state: %v", err)
	}
	res := h.get(h.URL + "/oauth/callback?state=" + url.QueryEscape(state))
	assertNoRedirect(t, res)
}

// TestAuthorizeRejectsUnknownClientAndRedirectURI covers DESIGN.md §2.1: the
// only two things the proxy validates, and the fact that it renders a page
// rather than redirecting to an unvalidated URI.
func TestAuthorizeRejectsUnknownClientAndRedirectURI(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	tests := []struct {
		name string
		q    url.Values
	}{
		{name: "unknown client", q: url.Values{"client_id": {"99999"}, "redirect_uri": {appRedirectURI}}},
		{name: "no client", q: url.Values{"redirect_uri": {appRedirectURI}}},
		{name: "no redirect_uri", q: url.Values{"client_id": {clientAID}}},
		{name: "suffix of an allowlisted uri", q: url.Values{"client_id": {clientAID}, "redirect_uri": {appRedirectURI + "/evil"}}},
		{name: "domain lookalike", q: url.Values{"client_id": {clientAID}, "redirect_uri": {"https://app.example.evil/strava/cb"}}},
		{name: "another client's uri", q: url.Values{"client_id": {clientAID}, "redirect_uri": {otherRedirectURI}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := h.get(h.URL + "/oauth/authorize?" + tc.q.Encode())
			assertNoRedirect(t, res)
			assertOAuthHardening(t, res)
		})
	}
}

// TestMobileAuthorizeUsesMobileUpstreamPath covers the mobile variant: same
// contract, different upstream path.
func TestMobileAuthorizeUsesMobileUpstreamPath(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	q := authorizeQuery()
	q.Set("state", "m")
	res := h.get(h.URL + "/oauth/mobile/authorize?" + q.Encode())
	assertStatus(t, res, http.StatusFound)
	if got, want := location(t, res).Path, "/oauth/mobile/authorize"; got != want {
		t.Errorf("upstream path = %q, want %q", got, want)
	}

	final := h.follow(h.follow(res))
	assertStatus(t, final, http.StatusFound)
	if location(t, final).Query().Get("code") == "" {
		t.Error("the mobile flow produced no wrapped code")
	}
}

// TestRedirectURIWithExistingQueryIsPreserved proves the callback rebuilds the
// redirect through net/url: the caller's own query parameters survive alongside
// the OAuth ones.
func TestRedirectURIWithExistingQueryIsPreserved(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	q := authorizeQuery()
	q.Set("redirect_uri", appRedirectAltURI)
	q.Set("state", "s")

	final := h.browserFlow(q)
	assertStatus(t, final, http.StatusFound)
	got := location(t, final).Query()
	if got.Get("tenant") != "acme" {
		t.Errorf("the redirect_uri's own query was lost: %v", got)
	}
	if got.Get("code") == "" || got.Get("state") != "s" {
		t.Errorf("OAuth parameters missing from the final redirect: %v", got)
	}
}

// TestCrossClientCodeTheft covers DESIGN.md §5: a wrapped code is bound to the
// virtual client whose flow minted it, so client B cannot spend client A's code
// even with its own perfectly valid credentials.
func TestCrossClientCodeTheft(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	q := authorizeQuery()
	q.Set("state", "victim")
	stolen := h.wrappedCode(q)

	h.Fake.Reset()
	res := h.exchange(clientBID, clientBSecret, stolen)
	assertFault(t, res, http.StatusBadRequest, faultInvalidCode)
	if got := h.Fake.TokenRequests(); got != 0 {
		t.Errorf("the stolen code reached Strava (%d upstream token requests)", got)
	}

	// The rightful owner can still spend it.
	res = h.exchange(clientAID, clientASecret, stolen)
	assertStatus(t, res, http.StatusOK)
}

// TestTokenEndpointCredentialFaults covers the proxy-minted rows of
// DESIGN.md §2.3, byte-for-byte.
func TestTokenEndpointCredentialFaults(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	code := h.wrappedCode(authorizeQuery())

	t.Run("unknown client_id", func(t *testing.T) {
		res := h.exchange("99999", clientASecret, code)
		assertFault(t, res, http.StatusBadRequest, faultInvalidClientID)
	})
	t.Run("wrong client_secret", func(t *testing.T) {
		res := h.exchange(clientAID, "wrong-secret", code)
		assertFault(t, res, http.StatusBadRequest, faultInvalidClientSecret)
	})
	t.Run("malformed code", func(t *testing.T) {
		res := h.exchange(clientAID, clientASecret, "k2.garbage.garbage")
		assertFault(t, res, http.StatusBadRequest, faultInvalidCode)
	})
	t.Run("revoke with bad basic credentials", func(t *testing.T) {
		res := h.postForm(h.URL+"/oauth/revoke", url.Values{"token": {"t"}},
			func(r *http.Request) { r.SetBasicAuth(clientAID, "wrong-secret") })
		assertFault(t, res, http.StatusUnauthorized, faultUnauthorized)
	})
	t.Run("revoke without basic credentials", func(t *testing.T) {
		res := h.postForm(h.URL+"/oauth/revoke", url.Values{"token": {"t"}})
		assertFault(t, res, http.StatusUnauthorized, faultUnauthorized)
	})
}

// TestTokenCredentialsInQueryString covers the Strava-fidelity requirement that
// token parameters are accepted from the query string as well as the body.
func TestTokenCredentialsInQueryString(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	code := h.wrappedCode(authorizeQuery())
	q := url.Values{"client_id": {clientAID}, "client_secret": {clientASecret}}
	res := h.postForm(h.URL+"/oauth/token?"+q.Encode(), url.Values{
		"code":       {code},
		"grant_type": {"authorization_code"},
	})
	assertStatus(t, res, http.StatusOK)
}

// TestBothTokenPathsAcceptBothGrants covers DESIGN.md §2.3: /oauth/token and
// /api/v3/oauth/token are interchangeable, and the latter wins over the
// /api/v3/ reverse-proxy catch-all.
func TestBothTokenPathsAcceptBothGrants(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"/oauth/token", "/api/v3/oauth/token"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)

			code := h.wrappedCode(authorizeQuery())
			res := h.postForm(h.URL+path, url.Values{
				"client_id":     {clientAID},
				"client_secret": {clientASecret},
				"code":          {code},
				"grant_type":    {"authorization_code"},
			})
			assertStatus(t, res, http.StatusOK)
			assertOAuthHardening(t, res)
			tok := decodeToken(t, res)

			res = h.postForm(h.URL+path, url.Values{
				"client_id":     {clientAID},
				"client_secret": {clientASecret},
				"grant_type":    {"refresh_token"},
				"refresh_token": {tok.RefreshToken},
			})
			assertStatus(t, res, http.StatusOK)

			// The virtual credentials must never have been forwarded upstream.
			for _, r := range h.Fake.RequestsTo("/api/v3/oauth/token") {
				if r.Form.Get("client_id") != realClientID {
					t.Errorf("upstream client_id = %q, want %q", r.Form.Get("client_id"), realClientID)
				}
			}
		})
	}
}

// TestStravaFaultsRelayedVerbatim covers the "relayed byte-for-byte" row of
// DESIGN.md §2.3: a code Strava rejects (here, one already burned) produces
// Strava's own Fault, not a proxy-minted one.
func TestStravaFaultsRelayedVerbatim(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	code := h.wrappedCode(authorizeQuery())
	if res := h.exchange(clientAID, clientASecret, code); res.StatusCode != http.StatusOK {
		t.Fatalf("first exchange failed: %d %s", res.StatusCode, res.Body)
	}
	// Replay: Strava enforces single use, the proxy does not.
	res := h.exchange(clientAID, clientASecret, code)
	assertFault(t, res, http.StatusBadRequest,
		`{"message":"Bad Request","errors":[{"resource":"AuthorizationCode","field":"code","code":"invalid"}]}`)

	// An unknown grant_type is Strava's error to mint, not the proxy's.
	res = h.postForm(h.URL+"/oauth/token", url.Values{
		"client_id":     {clientAID},
		"client_secret": {clientASecret},
		"grant_type":    {"client_credentials"},
	})
	assertFault(t, res, http.StatusBadRequest,
		`{"message":"Bad Request","errors":[{"resource":"Application","field":"grant_type","code":"invalid"}]}`)
}
