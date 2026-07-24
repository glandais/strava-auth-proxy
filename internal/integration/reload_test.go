package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/glandais/strava-auth-proxy/internal/config"
	"github.com/glandais/strava-auth-proxy/internal/fakestrava"
	"github.com/glandais/strava-auth-proxy/internal/upstream"
)

// clientEntry mirrors one record of the virtual client registry file.
type clientEntry struct {
	ClientID           string   `json:"client_id"`
	ClientSecret       string   `json:"client_secret"`
	RedirectURIs       []string `json:"redirect_uris"`
	RequireNonceCookie bool     `json:"require_nonce_cookie,omitempty"`
}

func defaultClientEntries() []clientEntry {
	return []clientEntry{
		{ClientID: clientAID, ClientSecret: clientASecret, RedirectURIs: []string{appRedirectURI, appRedirectAltURI}},
		{ClientID: clientBID, ClientSecret: clientBSecret, RedirectURIs: []string{otherRedirectURI}},
	}
}

func writeClientRegistry(t *testing.T, path string, entries []clientEntry) {
	t.Helper()
	b, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		t.Fatalf("marshalling the client registry: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("writing the client registry: %v", err)
	}
}

// newEnvHarness builds a proxy whose configuration comes from config.Load,
// exactly as the binary's would: environment scalars plus a client registry
// file. It is the only harness that can exercise config.Holder.Reload, and it
// mutates process-wide environment variables, so its tests must not run in
// parallel.
func newEnvHarness(t *testing.T, clientsPath string, opts ...harnessOpt) *harness {
	t.Helper()

	hc := &harnessConfig{
		stateTTL:      config.DefaultStateTTL,
		clientTimeout: upstream.ClientTimeout,
	}
	for _, o := range opts {
		o(hc)
	}

	fake := fakestrava.New(t, realClientID, realClientSecret)
	srv := httptest.NewUnstartedServer(nil)
	publicURL := "http://" + srv.Listener.Addr().String()

	upstreamURL := hc.upstreamURL
	if upstreamURL == "" {
		upstreamURL = fake.URL
	}

	t.Setenv(config.EnvStravaClientID, realClientID)
	t.Setenv(config.EnvStravaClientSecret, realClientSecret)
	t.Setenv(config.EnvPublicURL, publicURL)
	t.Setenv(config.EnvUpstreamBaseURL, upstreamURL)
	t.Setenv(config.EnvListenAddr, "127.0.0.1:0")
	t.Setenv(config.EnvAdminAddr, "127.0.0.1:0")
	t.Setenv(config.EnvDevAllowHTTP, "true")
	t.Setenv(config.EnvStateKeys, testStateKeySpec())
	t.Setenv(config.EnvStateTTL, hc.stateTTL.String())
	t.Setenv(config.EnvClientsFile, clientsPath)
	// Neutralise anything the ambient environment might contribute.
	t.Setenv(config.EnvClients, "")
	t.Setenv(config.EnvStravaClientSecret+"_FILE", "")
	t.Setenv(config.EnvPublicURL+"_FILE", "")
	t.Setenv(config.EnvStateKeys+"_FILE", "")
	t.Setenv(config.EnvTLSCertFile, "")
	t.Setenv(config.EnvTLSKeyFile, "")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return startHarness(t, fake, srv, config.NewHolder(cfg), hc)
}

// TestConfigHotReload covers DESIGN.md §4 and §6: the callback re-validates the
// virtual client and its redirect_uri against the *current* configuration, so a
// registry change that lands while the user is on Strava's consent page decides
// the outcome of an already-issued authorization.
//
// It is deliberately not parallel: it drives the real environment-based loader.
func TestConfigHotReload(t *testing.T) {
	clientsPath := filepath.Join(t.TempDir(), "clients.json")
	writeClientRegistry(t, clientsPath, defaultClientEntries())

	h := newEnvHarness(t, clientsPath)

	// An environment-loaded configuration drives the full flow, which is what
	// makes the in-process configurations the other tests build trustworthy.
	t.Run("env loaded config completes the flow", func(t *testing.T) {
		q := authorizeQuery()
		q.Set("state", "baseline")
		code := h.wrappedCode(q)
		res := h.exchange(clientAID, clientASecret, code)
		assertStatus(t, res, http.StatusOK)
	})

	t.Run("client removed mid flight fails the callback", func(t *testing.T) {
		// Start the flow: the browser is now "on Strava's consent page" and the
		// callback URL is in hand but not yet used.
		callbackURL := h.pendingCallbackURL(authorizeQuery())

		writeClientRegistry(t, clientsPath, []clientEntry{defaultClientEntries()[1]})
		if err := h.Holder.Reload(); err != nil {
			t.Fatalf("reload: %v", err)
		}
		if _, ok := h.Holder.Get().Client(clientAID); ok {
			t.Fatal("client A is still registered after the reload")
		}

		res := h.get(callbackURL)
		assertNoRedirect(t, res)
		assertOAuthHardening(t, res)
	})

	t.Run("redirect_uri revoked mid flight fails the callback", func(t *testing.T) {
		writeClientRegistry(t, clientsPath, defaultClientEntries())
		if err := h.Holder.Reload(); err != nil {
			t.Fatalf("restoring the registry: %v", err)
		}

		callbackURL := h.pendingCallbackURL(authorizeQuery())

		narrowed := defaultClientEntries()
		narrowed[0].RedirectURIs = []string{appRedirectAltURI} // appRedirectURI dropped
		writeClientRegistry(t, clientsPath, narrowed)
		if err := h.Holder.Reload(); err != nil {
			t.Fatalf("reload: %v", err)
		}

		res := h.get(callbackURL)
		assertNoRedirect(t, res)
	})

	t.Run("client kept completes the flow", func(t *testing.T) {
		writeClientRegistry(t, clientsPath, defaultClientEntries())
		if err := h.Holder.Reload(); err != nil {
			t.Fatalf("reload: %v", err)
		}

		callbackURL := h.pendingCallbackURL(authorizeQuery())
		res := h.get(callbackURL)
		assertStatus(t, res, http.StatusFound)

		code := location(t, res).Query().Get("code")
		if code == "" {
			t.Fatal("no wrapped code after a reload that kept the client")
		}
		assertStatus(t, h.exchange(clientAID, clientASecret, code), http.StatusOK)
	})

	t.Run("invalid reload keeps the previous configuration live", func(t *testing.T) {
		if err := os.WriteFile(clientsPath, []byte("{ not json"), 0o600); err != nil {
			t.Fatalf("corrupting the registry: %v", err)
		}
		if err := h.Holder.Reload(); err == nil {
			t.Fatal("Reload accepted a malformed registry")
		}
		// The previously validated configuration is still serving.
		q := authorizeQuery()
		q.Set("state", "still-alive")
		code := h.wrappedCode(q)
		assertStatus(t, h.exchange(clientAID, clientASecret, code), http.StatusOK)

		writeClientRegistry(t, clientsPath, defaultClientEntries())
	})

	// A newly added client is usable without a restart.
	t.Run("client added by reload is immediately usable", func(t *testing.T) {
		const newID, newSecret = "90003", "virtual-C-secret-11ab"
		entries := append(defaultClientEntries(), clientEntry{
			ClientID:     newID,
			ClientSecret: newSecret,
			RedirectURIs: []string{"https://third.example/cb"},
		})
		writeClientRegistry(t, clientsPath, entries)
		if err := h.Holder.Reload(); err != nil {
			t.Fatalf("reload: %v", err)
		}

		q := authorizeQuery()
		q.Set("client_id", newID)
		q.Set("redirect_uri", "https://third.example/cb")
		code := h.wrappedCode(q)
		assertStatus(t, h.exchange(newID, newSecret, code), http.StatusOK)
	})
}

// pendingCallbackURL drives the browser leg up to (but not through) the proxy
// callback, returning the URL Strava told the browser to visit next.
func (h *harness) pendingCallbackURL(q url.Values) string {
	h.t.Helper()
	toStrava := h.get(h.URL + "/oauth/authorize?" + q.Encode())
	assertStatus(h.t, toStrava, http.StatusFound)
	toCallback := h.follow(toStrava)
	assertStatus(h.t, toCallback, http.StatusFound)
	return location(h.t, toCallback).String()
}
