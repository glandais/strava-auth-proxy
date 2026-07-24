package upstream

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewTransportHardening(t *testing.T) {
	tr := NewTransport()

	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil: TLS floor unset")
	}
	if got := tr.TLSClientConfig.MinVersion; got != tls.VersionTLS12 {
		t.Errorf("TLS MinVersion = %#x, want %#x (TLS 1.2)", got, tls.VersionTLS12)
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("certificate verification is disabled")
	}
	if !tr.DisableCompression {
		t.Error("DisableCompression = false: gzip bodies would be transparently decoded and the caller's Accept-Encoding overwritten")
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 = false")
	}
	if tr.DialContext == nil {
		t.Error("DialContext is nil: dial timeout unset")
	}

	for _, tc := range []struct {
		name string
		got  interface{ String() string }
	}{
		{"TLSHandshakeTimeout", tr.TLSHandshakeTimeout},
		{"ResponseHeaderTimeout", tr.ResponseHeaderTimeout},
		{"ExpectContinueTimeout", tr.ExpectContinueTimeout},
		{"IdleConnTimeout", tr.IdleConnTimeout},
	} {
		if tc.got.String() == "0s" {
			t.Errorf("%s is unset", tc.name)
		}
	}
	if tr.MaxIdleConns <= 0 || tr.MaxIdleConnsPerHost <= 0 {
		t.Errorf("connection pool unsized: MaxIdleConns=%d MaxIdleConnsPerHost=%d",
			tr.MaxIdleConns, tr.MaxIdleConnsPerHost)
	}
	if other := NewTransport(); other == tr {
		t.Error("NewTransport returned a shared instance; each call must yield a fresh transport")
	}
}

func TestNewClientDoesNotFollowRedirects(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Location", "/elsewhere")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "must not be reached")
	}))
	defer srv.Close()

	resp, err := NewClient().Get(srv.URL + "/oauth/token")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302 returned as-is", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/elsewhere" {
		t.Errorf("Location = %q, want /elsewhere", got)
	}
	if hits != 1 {
		t.Errorf("upstream hits = %d, want exactly 1 (redirect must not be chased)", hits)
	}
}

func TestNewClientHasOverallTimeout(t *testing.T) {
	c := NewClient()
	if c.Timeout <= 0 {
		t.Error("client has no overall timeout")
	}
	if c.Timeout != ClientTimeout {
		t.Errorf("Timeout = %v, want %v", c.Timeout, ClientTimeout)
	}
	if c.Transport == nil {
		t.Fatal("client uses the default transport instead of the hardened one")
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Transport", c.Transport)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Error("client transport is not the hardened transport")
	}
}

// TestNoInsecureSkipVerifyOptIn asserts the package contains no code path that
// turns certificate verification off — not even flag-gated. The needle is
// assembled at runtime so this test file does not match itself.
func TestNoInsecureSkipVerifyOptIn(t *testing.T) {
	needle := "Insecure" + "SkipVerify"
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), needle) {
			t.Errorf("%s mentions %s", name, needle)
		}
	}
}
