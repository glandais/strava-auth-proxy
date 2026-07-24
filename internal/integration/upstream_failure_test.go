package integration

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glandais/strava-auth-proxy/internal/seal"
)

// deadUpstreamURL returns the URL of an address nothing is listening on: a
// listener is bound only long enough to reserve a port, then closed.
func deadUpstreamURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("closing the reserved listener: %v", err)
	}
	return "http://" + addr
}

// mintCode seals a wrapped authorization code without going through the browser
// leg, which is what lets the upstream-failure harnesses point somewhere other
// than the fake Strava.
func (h *harness) mintCode(clientID string) string {
	h.t.Helper()
	code, err := h.Ring.Seal(seal.DomainCode, seal.CodePayload{
		CID: clientID, SC: "raw-strava-code", IAT: time.Now().Unix(),
	})
	if err != nil {
		h.t.Fatalf("sealing a wrapped code: %v", err)
	}
	return code
}

// TestUpstreamUnavailable covers the 502 row of DESIGN.md §2.3 and §2.6:
// Strava is unreachable, on every leg that talks to it.
func TestUpstreamUnavailable(t *testing.T) {
	t.Parallel()
	h := newHarness(t, withUpstream(deadUpstreamURL(t)), withClientTimeout(5*time.Second))

	t.Run("token", func(t *testing.T) {
		t.Parallel()
		res := h.exchange(clientAID, clientASecret, h.mintCode(clientAID))
		assertFault(t, res, http.StatusBadGateway, faultUpstreamUnavailable)
		assertOAuthHardening(t, res)
	})
	t.Run("refresh", func(t *testing.T) {
		t.Parallel()
		res := h.refresh(clientAID, clientASecret, "some-refresh-token")
		assertFault(t, res, http.StatusBadGateway, faultUpstreamUnavailable)
	})
	t.Run("deauthorize", func(t *testing.T) {
		t.Parallel()
		res := h.postForm(h.URL+"/oauth/deauthorize", url.Values{"access_token": {"t"}})
		assertFault(t, res, http.StatusBadGateway, faultUpstreamUnavailable)
	})
	t.Run("revoke", func(t *testing.T) {
		t.Parallel()
		res := h.postForm(h.URL+"/oauth/revoke", url.Values{"token": {"t"}},
			func(r *http.Request) { r.SetBasicAuth(clientAID, clientASecret) })
		assertFault(t, res, http.StatusBadGateway, faultUpstreamUnavailable)
	})
	t.Run("api v3 reverse proxy", func(t *testing.T) {
		t.Parallel()
		res := h.get(h.URL + "/api/v3/athlete")
		assertFault(t, res, http.StatusBadGateway, faultUpstreamUnavailable)
	})
}

// TestUpstreamTimeout covers the 504 rows: Strava accepted the connection but
// never answered within the proxy's deadline.
func TestUpstreamTimeout(t *testing.T) {
	t.Parallel()

	t.Run("token", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, withClientTimeout(200*time.Millisecond))

		// Mint the code before the fake starts stalling, so only the token leg
		// is slow.
		code := h.wrappedCode(authorizeQuery())
		h.Fake.SetHang(800 * time.Millisecond)

		res := h.exchange(clientAID, clientASecret, code)
		assertFault(t, res, http.StatusGatewayTimeout, faultUpstreamTimeout)
		assertOAuthHardening(t, res)
	})

	t.Run("api v3 reverse proxy", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, withResponseHeaderTimeout(200*time.Millisecond))
		h.Fake.SetHang(800 * time.Millisecond)

		res := h.get(h.URL + "/api/v3/athlete")
		assertFault(t, res, http.StatusGatewayTimeout, faultUpstreamTimeout)
	})
}

// countingUpstream is a stand-in for a Strava brownout: it answers every
// request the same way and counts the attempts. fakestrava has no 5xx injection
// knob, and the no-retry invariant is precisely about what the proxy does when
// an upstream call fails ambiguously.
type countingUpstream struct {
	*httptest.Server
	n atomic.Int64
}

func (c *countingUpstream) attempts() int { return int(c.n.Load()) }

// newCountingUpstream starts a stub that answers every request with status and
// body, counting the attempts.
func newCountingUpstream(t *testing.T, status int, body string, delay time.Duration) *countingUpstream {
	t.Helper()
	c := &countingUpstream{}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.n.Add(1)
		if delay > 0 {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(delay):
			}
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(c.Server.Close)
	return c
}

// TestNoRetryOnUpstreamFailure covers design invariant 1: exactly one upstream
// attempt per caller request. Authorization codes are single use, so a retry
// after an ambiguous failure burns the code and turns a transient error into a
// permanent one.
func TestNoRetryOnUpstreamFailure(t *testing.T) {
	t.Parallel()

	const serverFault = `{"message":"Internal Error","errors":[]}`

	t.Run("authorization_code against a 5xx", func(t *testing.T) {
		t.Parallel()
		stub := newCountingUpstream(t, http.StatusInternalServerError, serverFault, 0)
		h := newHarness(t, withUpstream(stub.URL))

		res := h.exchange(clientAID, clientASecret, h.mintCode(clientAID))
		assertStatus(t, res, http.StatusInternalServerError)
		if string(res.Body) != serverFault {
			t.Errorf("body = %s, want %s", res.Body, serverFault)
		}
		if got := stub.attempts(); got != 1 {
			t.Errorf("upstream attempts = %d, want exactly 1", got)
		}
	})

	t.Run("refresh_token against a 5xx", func(t *testing.T) {
		t.Parallel()
		stub := newCountingUpstream(t, http.StatusServiceUnavailable, serverFault, 0)
		h := newHarness(t, withUpstream(stub.URL))

		res := h.refresh(clientAID, clientASecret, "r")
		assertStatus(t, res, http.StatusServiceUnavailable)
		if got := stub.attempts(); got != 1 {
			t.Errorf("upstream attempts = %d, want exactly 1", got)
		}
	})

	t.Run("timeout does not retry either", func(t *testing.T) {
		t.Parallel()
		stub := newCountingUpstream(t, http.StatusOK, "{}", 800*time.Millisecond)
		h := newHarness(t, withUpstream(stub.URL), withClientTimeout(200*time.Millisecond))

		res := h.exchange(clientAID, clientASecret, h.mintCode(clientAID))
		assertFault(t, res, http.StatusGatewayTimeout, faultUpstreamTimeout)
		if got := stub.attempts(); got != 1 {
			t.Errorf("upstream attempts = %d, want exactly 1", got)
		}
	})

	t.Run("reverse proxy does not retry", func(t *testing.T) {
		t.Parallel()
		stub := newCountingUpstream(t, http.StatusBadGateway, serverFault, 0)
		h := newHarness(t, withUpstream(stub.URL))

		res := h.get(h.URL + "/api/v3/athlete")
		assertStatus(t, res, http.StatusBadGateway)
		if string(res.Body) != serverFault {
			t.Errorf("body = %s, want %s", res.Body, serverFault)
		}
		if got := stub.attempts(); got != 1 {
			t.Errorf("upstream attempts = %d, want exactly 1", got)
		}
	})

	// A code the proxy accepts but Strava rejects must not be retried either:
	// the fake counts the attempts.
	t.Run("strava fault is not retried", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)

		code := h.wrappedCode(authorizeQuery())
		assertStatus(t, h.exchange(clientAID, clientASecret, code), http.StatusOK)

		h.Fake.Reset()
		res := h.exchange(clientAID, clientASecret, code) // replay: Strava says invalid
		assertStatus(t, res, http.StatusBadRequest)
		if got := h.Fake.TokenRequests(); got != 1 {
			t.Errorf("upstream attempts = %d, want exactly 1", got)
		}
	})
}
