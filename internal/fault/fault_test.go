package fault_test

import (
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/glandais/strava-auth-proxy/internal/fault"
)

var update = flag.Bool("update", false, "rewrite the testdata golden files")

// golden compares got against testdata/name byte-for-byte, rewriting the
// fixture instead when -update is passed.
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run: go test ./internal/fault/... -update)", path, err)
	}
	if string(got) != string(want) {
		t.Errorf("body mismatch for %s\n got: %q\nwant: %q", path, got, want)
	}
}

func TestWriters(t *testing.T) {
	tests := []struct {
		name       string
		golden     string
		write      func(http.ResponseWriter)
		wantStatus int
	}{
		{
			name:       "invalid client_id",
			golden:     "invalid_client_id.json",
			write:      fault.WriteInvalidClientID,
			wantStatus: http.StatusBadRequest,
		},
		{
			// 401, not 400: real Strava distinguishes an unknown client_id
			// (400 "Bad Request") from a known one presented with a wrong
			// secret (401 "Authorization Error"). Verified live against a real
			// application id; see docs/STRAVA-CONTRACT.md.
			name:       "invalid client_secret",
			golden:     "invalid_client_secret.json",
			write:      fault.WriteInvalidClientSecret,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid code",
			golden:     "invalid_code.json",
			write:      fault.WriteInvalidCode,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unauthorized",
			golden:     "unauthorized.json",
			write:      fault.WriteUnauthorized,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "upstream unavailable",
			golden:     "upstream_unavailable.json",
			write:      fault.WriteUpstreamUnavailable,
			wantStatus: http.StatusBadGateway,
		},
		{
			name:       "upstream timeout",
			golden:     "upstream_timeout.json",
			write:      fault.WriteUpstreamTimeout,
			wantStatus: http.StatusGatewayTimeout,
		},
		{
			name:   "generic write",
			golden: "generic.json",
			write: func(w http.ResponseWriter) {
				fault.Write(w, http.StatusTooManyRequests, fault.Fault{
					Message: "Rate Limit Exceeded",
					Errors: []fault.Error{{
						Resource: "Application",
						Field:    "rate limit",
						Code:     "exceeded",
					}},
				})
			},
			wantStatus: http.StatusTooManyRequests,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tt.write(rec)
			res := rec.Result()
			defer res.Body.Close()

			if res.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d", res.StatusCode, tt.wantStatus)
			}
			if got, want := res.Header.Get("Content-Type"), "application/json; charset=utf-8"; got != want {
				t.Errorf("Content-Type = %q, want %q", got, want)
			}
			body := rec.Body.Bytes()
			if got, want := res.Header.Get("Content-Length"), strconv.Itoa(len(body)); got != want {
				t.Errorf("Content-Length = %q, want %q", got, want)
			}
			if strings.HasSuffix(string(body), "\n") {
				t.Errorf("body has a trailing newline: %q", body)
			}
			if !json.Valid(body) {
				t.Errorf("body is not valid JSON: %q", body)
			}
			golden(t, tt.golden, body)
		})
	}
}

func TestWriteNormalisesNilErrors(t *testing.T) {
	rec := httptest.NewRecorder()
	fault.Write(rec, http.StatusBadRequest, fault.Fault{Message: "Bad Request"})

	if got, want := rec.Body.String(), `{"message":"Bad Request","errors":[]}`; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestFaultRoundTrip(t *testing.T) {
	rec := httptest.NewRecorder()
	fault.WriteInvalidCode(rec)

	var got fault.Fault
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := fault.Fault{
		Message: "Bad Request",
		Errors:  []fault.Error{{Resource: "AuthorizationCode", Field: "code", Code: "invalid"}},
	}
	if got.Message != want.Message || len(got.Errors) != 1 || got.Errors[0] != want.Errors[0] {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}
}

func TestWriteBadRequestPage(t *testing.T) {
	tests := []struct {
		name   string
		detail string
		golden string
	}{
		{name: "plain", detail: "Unknown client_id.", golden: "bad_request_page.html"},
		{name: "empty detail", detail: "", golden: "bad_request_page_default.html"},
		{name: "escaped", detail: `<script>alert("xss")</script> & 'quotes'`, golden: "bad_request_page_escaped.html"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			fault.WriteBadRequestPage(rec, tt.detail)
			res := rec.Result()
			defer res.Body.Close()

			if res.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", res.StatusCode)
			}
			if got, want := res.Header.Get("Content-Type"), "text/html; charset=utf-8"; got != want {
				t.Errorf("Content-Type = %q, want %q", got, want)
			}
			body := rec.Body.Bytes()
			if got, want := res.Header.Get("Content-Length"), strconv.Itoa(len(body)); got != want {
				t.Errorf("Content-Length = %q, want %q", got, want)
			}
			golden(t, tt.golden, body)
		})
	}
}

func TestWriteBadRequestPageEscapesScript(t *testing.T) {
	rec := httptest.NewRecorder()
	fault.WriteBadRequestPage(rec, `<script>alert(1)</script>`)

	body := rec.Body.String()
	if strings.Contains(body, "<script>") {
		t.Fatalf("reflected script tag survived escaping: %q", body)
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("detail not html-escaped: %q", body)
	}
}

// The page must never echo request parameters: no code, state or secret can be
// reflected even if a caller were careless with the detail string source.
func TestWriteBadRequestPageHasNoQueryEcho(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/oauth/callback?code=RAWCODE&state=SEALEDSTATE&client_secret=SUPERSECRET", nil)
	fault.WriteBadRequestPage(rec, "Invalid or expired state.")

	body := rec.Body.String()
	for _, needle := range []string{"RAWCODE", "SEALEDSTATE", "SUPERSECRET", req.URL.RawQuery, "?"} {
		if strings.Contains(body, needle) {
			t.Errorf("page contains %q:\n%s", needle, body)
		}
	}
}
