package httpmid_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glandais/strava-auth-proxy/internal/httpmid"
)

// spyHandler is a slog.Handler that captures every record it is given, along
// with the attrs and groups attached to the logger that produced it. It exists
// so tests can sweep the complete rendered content of every log line for
// secrets, not just the attrs the middleware passed directly.
type spyHandler struct {
	mu     *sync.Mutex
	lines  *[]string
	prefix []slog.Attr
	groups []string
}

func newSpy() *spyHandler {
	return &spyHandler{mu: new(sync.Mutex), lines: new([]string)}
}

func (h *spyHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *spyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.prefix = append(append([]slog.Attr(nil), h.prefix...), attrs...)
	return &c
}

func (h *spyHandler) WithGroup(name string) slog.Handler {
	c := *h
	c.groups = append(append([]string(nil), h.groups...), name)
	return &c
}

func (h *spyHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	fmt.Fprintf(&b, "level=%s msg=%q groups=%v", r.Level, r.Message, h.groups)
	for _, a := range h.prefix {
		writeAttr(&b, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(&b, a)
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	*h.lines = append(*h.lines, b.String())
	return nil
}

// writeAttr renders an attr, recursing into groups, so nothing an attr carries
// can hide from the secret sweep.
func writeAttr(b *strings.Builder, a slog.Attr) {
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		fmt.Fprintf(b, " %s=[", a.Key)
		for _, g := range v.Group() {
			writeAttr(b, g)
		}
		b.WriteString("]")
		return
	}
	fmt.Fprintf(b, " %s=%q", a.Key, v.String())
}

func (h *spyHandler) records() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), *h.lines...)
}

func (h *spyHandler) only(t *testing.T) string {
	t.Helper()
	recs := h.records()
	if len(recs) != 1 {
		t.Fatalf("got %d log records, want 1: %v", len(recs), recs)
	}
	return recs[0]
}

func spyLogger() (*slog.Logger, *spyHandler) {
	h := newSpy()
	return slog.New(h), h
}

// ---------------------------------------------------------------------------
// SecurityHeaders
// ---------------------------------------------------------------------------

func TestSecurityHeaders(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantStatus int
	}{
		{
			name: "plain 200",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "302 redirect",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://app.example/cb?code=x", http.StatusFound)
			},
			wantStatus: http.StatusFound,
		},
		{
			name: "writes body before any WriteHeader",
			handler: func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, "early bytes")
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "writes nothing at all",
			handler: func(w http.ResponseWriter, r *http.Request) {
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "error status",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "nope", http.StatusBadRequest)
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			httpmid.SecurityHeaders(tt.handler).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/oauth/callback", nil))

			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
			if got := rr.Header().Get(httpmid.HeaderReferrerPolicy); got != httpmid.ReferrerPolicyValue {
				t.Errorf("%s = %q, want %q", httpmid.HeaderReferrerPolicy, got, httpmid.ReferrerPolicyValue)
			}
			if got := rr.Header().Get(httpmid.HeaderCacheControl); got != httpmid.CacheControlValue {
				t.Errorf("%s = %q, want %q", httpmid.HeaderCacheControl, got, httpmid.CacheControlValue)
			}
		})
	}
}

func TestSecurityHeadersOverEndToEndServer(t *testing.T) {
	srv := httptest.NewServer(httpmid.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/oauth/token")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get(httpmid.HeaderReferrerPolicy); got != httpmid.ReferrerPolicyValue {
		t.Errorf("%s = %q, want %q", httpmid.HeaderReferrerPolicy, got, httpmid.ReferrerPolicyValue)
	}
	if got := resp.Header.Get(httpmid.HeaderCacheControl); got != httpmid.CacheControlValue {
		t.Errorf("%s = %q, want %q", httpmid.HeaderCacheControl, got, httpmid.CacheControlValue)
	}
}

// ---------------------------------------------------------------------------
// AccessLog: the redaction invariant
// ---------------------------------------------------------------------------

// TestAccessLogNeverLogsQueryString is the tested invariant of DESIGN.md §5:
// no fragment of an OAuth query string may ever reach the log.
func TestAccessLogNeverLogsQueryString(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		target    string
		body      string
		forbidden []string
	}{
		{
			name:      "callback with authorization code",
			method:    http.MethodGet,
			target:    "/oauth/callback?code=SECRETCODE&state=X&scope=read,activity:read_all",
			forbidden: []string{"SECRETCODE", "code=", "state=", "scope="},
		},
		{
			name:   "token endpoint with client secret in query",
			method: http.MethodPost,
			target: "/oauth/token?client_secret=SECRETVAL&client_id=42",
			// "client_id=" itself is a legitimate log field name; the query
			// *value* 42 must be the thing that never appears.
			forbidden: []string{"SECRETVAL", "client_secret", `client_id="42"`, "=42"},
		},
		{
			name:      "token endpoint with client secret in form body",
			method:    http.MethodPost,
			target:    "/oauth/token",
			body:      "grant_type=authorization_code&client_secret=SECRETVAL&code=SECRETCODE",
			forbidden: []string{"SECRETVAL", "SECRETCODE", "client_secret", "code="},
		},
		{
			name:      "denial callback",
			method:    http.MethodGet,
			target:    "/oauth/callback?error=access_denied&state=SECRETVAL",
			forbidden: []string{"SECRETVAL", "access_denied", "error="},
		},
		{
			name:      "unrouted probe carrying a secret",
			method:    http.MethodGet,
			target:    "/nope?token=SECRETVAL",
			forbidden: []string{"SECRETVAL", "token="},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, spy := spyLogger()

			mux := http.NewServeMux()
			mux.HandleFunc("GET /oauth/callback", func(w http.ResponseWriter, r *http.Request) {
				// A realistic handler reads the secret-bearing params and
				// publishes only the virtual client id.
				_ = r.URL.Query().Get("code")
				httpmid.SetClientID(r, "virtual-1")
				http.Redirect(w, r, "https://app.example/cb", http.StatusFound)
			})
			mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				httpmid.SetClientID(r, "virtual-1")
				io.WriteString(w, `{"access_token":"SUPERSECRETTOKEN"}`)
			})

			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}
			req := httptest.NewRequest(tt.method, tt.target, body)
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			req.Header.Set("Authorization", "Bearer SECRETVAL")
			req.AddCookie(&http.Cookie{Name: "__Host-sap-nonce", Value: "SECRETVAL"})

			httpmid.AccessLog(logger, httpmid.SecurityHeaders(mux)).ServeHTTP(httptest.NewRecorder(), req)

			recs := spy.records()
			if len(recs) == 0 {
				t.Fatal("no log records captured")
			}
			for i, rec := range recs {
				for _, bad := range tt.forbidden {
					if strings.Contains(rec, bad) {
						t.Errorf("record %d contains forbidden %q:\n%s", i, bad, rec)
					}
				}
				for _, bad := range []string{"SUPERSECRETTOKEN", "Bearer", "__Host-sap-nonce"} {
					if strings.Contains(rec, bad) {
						t.Errorf("record %d contains forbidden %q:\n%s", i, bad, rec)
					}
				}
			}
		})
	}
}

func TestAccessLogRedactsPresentQueryOnly(t *testing.T) {
	tests := []struct {
		name      string
		target    string
		wantQuery bool
	}{
		{name: "with query", target: "/oauth/callback?code=SECRETCODE", wantQuery: true},
		{name: "empty query marker", target: "/oauth/callback?", wantQuery: false},
		{name: "without query", target: "/oauth/callback", wantQuery: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, spy := spyLogger()
			h := httpmid.AccessLog(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, tt.target, nil))

			rec := spy.only(t)
			hasQuery := strings.Contains(rec, `query="`+httpmid.RedactedQuery+`"`)
			if hasQuery != tt.wantQuery {
				t.Errorf("query attr present = %v, want %v:\n%s", hasQuery, tt.wantQuery, rec)
			}
			if !strings.Contains(rec, `path="/oauth/callback"`) {
				t.Errorf("path attr missing:\n%s", rec)
			}
		})
	}
}

func TestAccessLogSanitisesPath(t *testing.T) {
	logger, spy := spyLogger()
	h := httpmid.AccessLog(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/oauth/%0alevel=ERROR%20msg=forged/"+strings.Repeat("a", 400), nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	rec := spy.only(t)
	if strings.Contains(rec, "\n") {
		t.Errorf("logged path smuggled a newline:\n%q", rec)
	}
	if strings.Contains(rec, strings.Repeat("a", 400)) {
		t.Errorf("logged path was not truncated:\n%s", rec)
	}
}

// ---------------------------------------------------------------------------
// AccessLog: fields
// ---------------------------------------------------------------------------

func TestAccessLogFields(t *testing.T) {
	logger, spy := spyLogger()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		httpmid.SetClientID(r, "virtual-42")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, "0123456789")
	})

	req := httptest.NewRequest(http.MethodPost, "/oauth/token?client_secret=SECRETVAL", nil)
	httpmid.AccessLog(logger, mux).ServeHTTP(httptest.NewRecorder(), req)

	rec := spy.only(t)
	for _, want := range []string{
		`msg="http request"`,
		`method="POST"`,
		`pattern="POST /oauth/token"`,
		`path="/oauth/token"`,
		`status="201"`,
		`bytes="10"`,
		`client_id="virtual-42"`,
		`query="` + httpmid.RedactedQuery + `"`,
		"latency=",
		"level=INFO",
	} {
		if !strings.Contains(rec, want) {
			t.Errorf("record missing %q:\n%s", want, rec)
		}
	}
}

func TestAccessLogStatusAndLevel(t *testing.T) {
	tests := []struct {
		name      string
		handler   http.HandlerFunc
		wantAttrs []string
	}{
		{
			name:      "implicit 200",
			handler:   func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hi") },
			wantAttrs: []string{`status="200"`, `bytes="2"`, "level=INFO"},
		},
		{
			name:      "no write at all",
			handler:   func(w http.ResponseWriter, r *http.Request) {},
			wantAttrs: []string{`status="200"`, `bytes="0"`, "level=INFO"},
		},
		{
			name:      "redirect",
			handler:   func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusFound) },
			wantAttrs: []string{`status="302"`, "level=INFO"},
		},
		{
			name:      "server error logs at warn",
			handler:   func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) },
			wantAttrs: []string{`status="502"`, "level=WARN"},
		},
		{
			name: "only first status recorded",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				w.WriteHeader(http.StatusOK) // net/http ignores the second
			},
			wantAttrs: []string{`status="400"`},
		},
		{
			name: "informational status is not the final status",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusEarlyHints)
				w.WriteHeader(http.StatusOK)
			},
			wantAttrs: []string{`status="200"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, spy := spyLogger()
			httpmid.AccessLog(logger, tt.handler).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))

			rec := spy.only(t)
			for _, want := range tt.wantAttrs {
				if !strings.Contains(rec, want) {
					t.Errorf("record missing %q:\n%s", want, rec)
				}
			}
		})
	}
}

func TestAccessLogUnroutedRequestHasEmptyPattern(t *testing.T) {
	logger, spy := spyLogger()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth/token", func(w http.ResponseWriter, r *http.Request) {})

	httpmid.AccessLog(logger, mux).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/unknown", nil))

	rec := spy.only(t)
	if !strings.Contains(rec, `pattern=""`) {
		t.Errorf("want empty pattern:\n%s", rec)
	}
	if !strings.Contains(rec, `status="404"`) {
		t.Errorf("want 404 status:\n%s", rec)
	}
}

func TestAccessLogNilLoggerUsesDefault(t *testing.T) {
	spy := newSpy()
	prev := slog.Default()
	slog.SetDefault(slog.New(spy))
	defer slog.SetDefault(prev)

	httpmid.AccessLog(nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/oauth/token", nil))

	if rec := spy.only(t); !strings.Contains(rec, `path="/oauth/token"`) {
		t.Errorf("default logger did not receive the record:\n%s", rec)
	}
}

func TestAccessLogPreservesLoggerAttrsAndGroups(t *testing.T) {
	spy := newSpy()
	logger := slog.New(spy).With(slog.String("svc", "proxy"))

	httpmid.AccessLog(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/oauth/token?code=SECRETCODE", nil))

	rec := spy.only(t)
	if !strings.Contains(rec, `svc="proxy"`) {
		t.Errorf("logger attrs lost:\n%s", rec)
	}
	if strings.Contains(rec, "SECRETCODE") {
		t.Errorf("secret leaked through a decorated logger:\n%s", rec)
	}
}

// ---------------------------------------------------------------------------
// SetClientID
// ---------------------------------------------------------------------------

func TestSetClientID(t *testing.T) {
	tests := []struct {
		name string
		set  func(r *http.Request)
		want string
	}{
		{name: "not called", set: func(*http.Request) {}, want: ""},
		{name: "empty id ignored", set: func(r *http.Request) { httpmid.SetClientID(r, "") }, want: ""},
		{name: "nil request ignored", set: func(*http.Request) { httpmid.SetClientID(nil, "x") }, want: ""},
		{name: "set once", set: func(r *http.Request) { httpmid.SetClientID(r, "virtual-1") }, want: "virtual-1"},
		{
			name: "last write wins",
			set: func(r *http.Request) {
				httpmid.SetClientID(r, "virtual-1")
				httpmid.SetClientID(r, "virtual-2")
			},
			want: "virtual-2",
		},
		{
			name: "survives a derived request",
			set: func(r *http.Request) {
				httpmid.SetClientID(r.WithContext(context.WithValue(r.Context(), struct{}{}, 1)), "virtual-9")
			},
			want: "virtual-9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, spy := spyLogger()
			h := httpmid.AccessLog(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tt.set(r)
			}))
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/oauth/token", nil))

			rec := spy.only(t)
			hasID := strings.Contains(rec, `client_id="`+tt.want+`"`)
			if tt.want == "" {
				if strings.Contains(rec, "client_id=") {
					t.Errorf("client_id logged although never set:\n%s", rec)
				}
				return
			}
			if !hasID {
				t.Errorf("client_id %q missing:\n%s", tt.want, rec)
			}
		})
	}
}

func TestSetClientIDWithoutAccessLogIsNoOp(t *testing.T) {
	// Must not panic when the middleware is absent (e.g. the admin mux).
	req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	httpmid.SetClientID(req, "virtual-1")
}

func TestSetClientIDFromAnotherGoroutine(t *testing.T) {
	logger, spy := spyLogger()
	h := httpmid.AccessLog(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		done := make(chan struct{})
		go func() {
			defer close(done)
			httpmid.SetClientID(r, "virtual-async")
		}()
		<-done
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/oauth/token", nil))

	if rec := spy.only(t); !strings.Contains(rec, `client_id="virtual-async"`) {
		t.Errorf("client_id set off-goroutine missing:\n%s", rec)
	}
}

// ---------------------------------------------------------------------------
// Wrapped ResponseWriter behaviour
// ---------------------------------------------------------------------------

func TestAccessLogPreservesFlushing(t *testing.T) {
	logger, spy := spyLogger()

	flushed := make(chan struct{}, 1)
	srv := httptest.NewServer(httpmid.AccessLog(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "chunk1")
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("ResponseController.Flush: %v", err)
		}
		flushed <- struct{}{}
		io.WriteString(w, "chunk2")
	})))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/oauth/token")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	select {
	case <-flushed:
	case <-time.After(5 * time.Second):
		t.Fatal("handler never flushed")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "chunk1chunk2" {
		t.Errorf("body = %q, want %q", body, "chunk1chunk2")
	}
	if rec := spy.only(t); !strings.Contains(rec, `bytes="12"`) {
		t.Errorf("byte count wrong:\n%s", rec)
	}
}

func TestAccessLogSupportsLegacyFlusher(t *testing.T) {
	logger, _ := spyLogger()
	var ok bool
	h := httpmid.AccessLog(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok = w.(http.Flusher)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/oauth/token", nil))
	if !ok {
		t.Error("wrapped ResponseWriter no longer implements http.Flusher")
	}
}

func TestMiddlewareOrderHeadersAndLog(t *testing.T) {
	logger, spy := spyLogger()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		httpmid.SetClientID(r, "virtual-1")
		http.Redirect(w, r, "https://app.example/cb?code=WRAPPEDCODE&state=CALLERSTATE", http.StatusFound)
	})

	rr := httptest.NewRecorder()
	httpmid.AccessLog(logger, httpmid.SecurityHeaders(mux)).
		ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/oauth/callback?code=SECRETCODE&state=X", nil))

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	if got := rr.Header().Get(httpmid.HeaderReferrerPolicy); got != httpmid.ReferrerPolicyValue {
		t.Errorf("%s = %q on a 302", httpmid.HeaderReferrerPolicy, got)
	}
	if got := rr.Header().Get(httpmid.HeaderCacheControl); got != httpmid.CacheControlValue {
		t.Errorf("%s = %q on a 302", httpmid.HeaderCacheControl, got)
	}

	rec := spy.only(t)
	// The Location header the handler emitted carries a code too: it must not
	// reach the log either.
	for _, bad := range []string{"SECRETCODE", "WRAPPEDCODE", "CALLERSTATE", "code=", "Location"} {
		if strings.Contains(rec, bad) {
			t.Errorf("record contains forbidden %q:\n%s", bad, rec)
		}
	}
}
