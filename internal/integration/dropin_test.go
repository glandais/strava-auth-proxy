package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// TestDropInWithXOAuth2 is the literal "swap the URL" acceptance test of
// DESIGN.md §6.
//
// An unmodified golang.org/x/oauth2 client is pointed at the proxy with nothing
// but a virtual credential and the two endpoint URLs changed, and it completes
// the whole dance: authorization URL, redirect, code exchange, and a refresh
// through a TokenSource. golang.org/x/oauth2 is the module's only third-party
// dependency and is test-only; TestProductionBinaryHasNoThirdPartyDependencies
// enforces that.
func TestDropInWithXOAuth2(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		style oauth2.AuthStyle
	}{
		// What a caller would configure for Strava, which wants the credentials
		// in the request body.
		{name: "credentials in params", style: oauth2.AuthStyleInParams},
		// The library's default. It probes with HTTP Basic first, gets the
		// proxy's Strava-shaped client_id fault, and falls back to params —
		// exactly what it does against Strava itself.
		{name: "auth style auto detected", style: oauth2.AuthStyleAutoDetect},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			h.Fake.SetAthleteJSON([]byte(athleteJSON))

			conf := &oauth2.Config{
				ClientID:     clientAID,
				ClientSecret: clientASecret,
				RedirectURL:  appRedirectURI,
				Scopes:       []string{"read", "activity:read_all"},
				Endpoint: oauth2.Endpoint{
					AuthURL:   h.URL + "/oauth/authorize",
					TokenURL:  h.URL + "/oauth/token",
					AuthStyle: tc.style,
				},
			}

			const callerState = "x-oauth2-csrf-state"
			authURL := conf.AuthCodeURL(callerState, oauth2.SetAuthURLParam("approval_prompt", "auto"))

			// The library's own authorization URL, driven straight through the
			// proxy and the fake Strava.
			toStrava := h.get(authURL)
			assertStatus(t, toStrava, http.StatusFound)
			toCallback := h.follow(toStrava)
			assertStatus(t, toCallback, http.StatusFound)
			toApp := h.follow(toCallback)
			assertStatus(t, toApp, http.StatusFound)

			appURL := location(t, toApp)
			if got := appURL.Query().Get("state"); got != callerState {
				t.Errorf("state = %q, want %q", got, callerState)
			}
			code := appURL.Query().Get("code")
			if code == "" {
				t.Fatal("the library's flow produced no authorization code")
			}

			// The parameters the library produced reached Strava untouched.
			stravaAuth := h.Fake.RequestsTo("/oauth/authorize")
			if len(stravaAuth) != 1 {
				t.Fatalf("fake saw %d authorize requests, want 1", len(stravaAuth))
			}
			sq := stravaAuth[0].Form
			if got, want := sq.Get("response_type"), "code"; got != want {
				t.Errorf("upstream response_type = %q, want %q", got, want)
			}
			if got, want := sq.Get("scope"), strings.Join(conf.Scopes, " "); got != want {
				t.Errorf("upstream scope = %q, want the library's own %q", got, want)
			}
			if got, want := sq.Get("approval_prompt"), "auto"; got != want {
				t.Errorf("upstream approval_prompt = %q, want %q", got, want)
			}

			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, h.Client)

			h.Fake.Reset()
			tok, err := conf.Exchange(ctx, code)
			if err != nil {
				t.Fatalf("oauth2 Exchange: %v", err)
			}
			if !tok.Valid() {
				t.Fatal("oauth2 returned an invalid token")
			}
			if tok.TokenType != "Bearer" || tok.AccessToken == "" || tok.RefreshToken == "" {
				t.Errorf("token is incomplete: type=%q access=%v refresh=%v",
					tok.TokenType, tok.AccessToken != "", tok.RefreshToken != "")
			}
			if tok.Expiry.IsZero() || tok.Expiry.Before(time.Now()) {
				t.Errorf("token expiry = %s, want a future instant", tok.Expiry)
			}
			// Whatever the auth-style probe did locally, exactly one attempt
			// reached Strava.
			if got := h.Fake.TokenRequests(); got != 1 {
				t.Errorf("upstream token requests = %d, want exactly 1", got)
			}

			// The undocumented parts of Strava's response survive the library's
			// own parsing, because the proxy relayed them verbatim.
			athlete, ok := tok.Extra("athlete").(map[string]any)
			if !ok {
				t.Fatalf("athlete missing from the token response: %T", tok.Extra("athlete"))
			}
			if athlete["username"] != "fakeathlete" {
				t.Errorf("athlete.username = %v, want fakeathlete", athlete["username"])
			}
			if _, ok := athlete["sap_undocumented_extra"]; !ok {
				t.Error("the undocumented athlete field did not reach the library")
			}

			// Refresh through the library's TokenSource, driven by an expired
			// access token exactly as a long-lived client would.
			stale := &oauth2.Token{
				AccessToken:  tok.AccessToken,
				RefreshToken: tok.RefreshToken,
				TokenType:    tok.TokenType,
				Expiry:       time.Now().Add(-time.Hour),
			}
			refreshed, err := conf.TokenSource(ctx, stale).Token()
			if err != nil {
				t.Fatalf("oauth2 TokenSource refresh: %v", err)
			}
			if !refreshed.Valid() {
				t.Fatal("the refreshed token is invalid")
			}
			if refreshed.AccessToken == tok.AccessToken {
				t.Error("the refresh returned the same access token")
			}

			// And the refreshed token works against the reverse-proxied API.
			res := h.get(h.URL+"/api/v3/athlete", func(r *http.Request) {
				refreshed.SetAuthHeader(r)
			})
			assertStatus(t, res, http.StatusOK)
			echo := decodeEcho(t, res.Body)
			if got, want := echo.Headers["Authorization"], "Bearer "+refreshed.AccessToken; len(got) != 1 || got[0] != want {
				t.Error("the library's Authorization header did not reach Strava byte-for-byte")
			}
		})
	}
}
