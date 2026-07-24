package fakestrava_test

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glandais/strava-auth-proxy/internal/fakestrava"
)

const (
	realID     = "12345"
	realSecret = "real-strava-secret"
	appCB      = "https://app.example/cb"
)

// noRedirectClient never follows redirects, so tests can inspect the 302 the
// authorize endpoints emit.
func noRedirectClient() *http.Client {
	return &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// authorize drives the authorize endpoint and returns the parsed Location.
func authorize(t *testing.T, s *fakestrava.Server, path string, q url.Values) *url.URL {
	t.Helper()
	resp, err := noRedirectClient().Get(s.URL + path + "?" + q.Encode())
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s: status = %d, body = %s; want 302", path, resp.StatusCode, body)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing Location: %v", err)
	}
	return loc
}

// postForm posts form values and returns the response.
func postForm(t *testing.T, s *fakestrava.Server, path string, form url.Values, tweak func(*http.Request)) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, s.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if tweak != nil {
		tweak(req)
	}
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

// decode reads a JSON body into dst and returns the raw bytes.
func decode(t *testing.T, resp *http.Response, dst any) []byte {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if dst != nil {
		if err := json.Unmarshal(body, dst); err != nil {
			t.Fatalf("unmarshalling %q: %v", body, err)
		}
	}
	return body
}

// tokenBody mirrors the documented token response.
type tokenBody struct {
	TokenType    string          `json:"token_type"`
	ExpiresAt    int64           `json:"expires_at"`
	ExpiresIn    int             `json:"expires_in"`
	RefreshToken string          `json:"refresh_token"`
	AccessToken  string          `json:"access_token"`
	Athlete      json.RawMessage `json:"athlete"`
}

type faultBody struct {
	Message string `json:"message"`
	Errors  []struct {
		Resource string `json:"resource"`
		Field    string `json:"field"`
		Code     string `json:"code"`
	} `json:"errors"`
}

// codeFor runs the authorize leg and returns the minted code.
func codeFor(t *testing.T, s *fakestrava.Server) string {
	t.Helper()
	loc := authorize(t, s, "/oauth/authorize", url.Values{
		"client_id":     {realID},
		"redirect_uri":  {appCB},
		"response_type": {"code"},
		"scope":         {"read,activity:read_all"},
		"state":         {"st"},
	})
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("authorize returned no code: %s", loc)
	}
	return code
}

func TestAuthorizeSuccess(t *testing.T) {
	t.Parallel()
	s := fakestrava.New(t, realID, realSecret)

	for _, path := range []string{"/oauth/authorize", "/oauth/mobile/authorize"} {
		t.Run(path, func(t *testing.T) {
			loc := authorize(t, s, path, url.Values{
				"client_id":     {realID},
				"redirect_uri":  {appCB + "?keep=1"},
				"response_type": {"code"},
				"scope":         {"read activity:read_all"},
				"state":         {"opaque state"},
			})
			q := loc.Query()
			if loc.Scheme+"://"+loc.Host+loc.Path != appCB {
				t.Errorf("redirect target = %q, want %q", loc, appCB)
			}
			if q.Get("keep") != "1" {
				t.Errorf("pre-existing query lost: %s", loc)
			}
			if q.Get("code") == "" {
				t.Error("no code in redirect")
			}
			// Space-delimited request, comma-delimited callback.
			if got := q.Get("scope"); got != "read,activity:read_all" {
				t.Errorf("scope = %q, want %q", got, "read,activity:read_all")
			}
			if got := q.Get("state"); got != "opaque state" {
				t.Errorf("state = %q, want %q", got, "opaque state")
			}
			if q.Has("error") {
				t.Errorf("unexpected error param: %s", loc)
			}
		})
	}
}

func TestAuthorizeKnobs(t *testing.T) {
	t.Parallel()

	t.Run("granted scope subset", func(t *testing.T) {
		s := fakestrava.New(t, realID, realSecret)
		s.SetGrantedScope("read")
		loc := authorize(t, s, "/oauth/authorize", url.Values{
			"client_id":    {realID},
			"redirect_uri": {appCB},
			"scope":        {"read,activity:read_all"},
		})
		if got := loc.Query().Get("scope"); got != "read" {
			t.Errorf("scope = %q, want %q", got, "read")
		}
	})

	t.Run("error redirect", func(t *testing.T) {
		s := fakestrava.New(t, realID, realSecret)
		s.SetAuthorizeError("access_denied")
		loc := authorize(t, s, "/oauth/authorize", url.Values{
			"client_id":    {realID},
			"redirect_uri": {appCB},
			"state":        {"st"},
		})
		q := loc.Query()
		if got := q.Get("error"); got != "access_denied" {
			t.Errorf("error = %q, want access_denied", got)
		}
		if q.Has("code") {
			t.Errorf("code present on the denial leg: %s", loc)
		}
		if got := q.Get("state"); got != "st" {
			t.Errorf("state = %q, want st", got)
		}
	})

	t.Run("no state means no state", func(t *testing.T) {
		s := fakestrava.New(t, realID, realSecret)
		loc := authorize(t, s, "/oauth/authorize", url.Values{
			"client_id":    {realID},
			"redirect_uri": {appCB},
		})
		if loc.Query().Has("state") {
			t.Errorf("state echoed although none was sent: %s", loc)
		}
	})
}

func TestAuthorizeRejectsBadInput(t *testing.T) {
	t.Parallel()
	s := fakestrava.New(t, realID, realSecret)

	tests := []struct {
		name  string
		query url.Values
		field string
	}{
		{"wrong client_id", url.Values{"client_id": {"99999"}, "redirect_uri": {appCB}}, "client_id"},
		{"missing client_id", url.Values{"redirect_uri": {appCB}}, "client_id"},
		{"missing redirect_uri", url.Values{"client_id": {realID}}, "redirect_uri"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := noRedirectClient().Get(s.URL + "/oauth/authorize?" + tc.query.Encode())
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			var f faultBody
			decode(t, resp, &f)
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
			if len(f.Errors) != 1 || f.Errors[0].Field != tc.field || f.Errors[0].Code != "invalid" {
				t.Errorf("fault = %+v, want field %q", f, tc.field)
			}
		})
	}
}

func TestTokenAuthorizationCodeGrant(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"/api/v3/oauth/token", "/oauth/token"} {
		t.Run(path, func(t *testing.T) {
			s := fakestrava.New(t, realID, realSecret)
			code := codeFor(t, s)

			resp := postForm(t, s, path, url.Values{
				"client_id":     {realID},
				"client_secret": {realSecret},
				"code":          {code},
				"grant_type":    {"authorization_code"},
			}, nil)
			var tok tokenBody
			decode(t, resp, &tok)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			if tok.TokenType != "Bearer" {
				t.Errorf("token_type = %q, want Bearer", tok.TokenType)
			}
			if tok.AccessToken == "" || tok.RefreshToken == "" {
				t.Errorf("empty tokens: %+v", tok)
			}
			if tok.ExpiresIn != 21600 {
				t.Errorf("expires_in = %d, want 21600", tok.ExpiresIn)
			}
			if tok.ExpiresAt <= time.Now().Unix() {
				t.Errorf("expires_at = %d, want a future epoch", tok.ExpiresAt)
			}
			var athlete map[string]any
			if err := json.Unmarshal(tok.Athlete, &athlete); err != nil {
				t.Fatalf("athlete missing or unparsable: %v", err)
			}
			if athlete["id"] == nil || athlete["resource_state"] == nil {
				t.Errorf("athlete = %v, want a SummaryAthlete", athlete)
			}
			if n := s.TokenRequests(); n != 1 {
				t.Errorf("TokenRequests = %d, want 1", n)
			}
		})
	}
}

func TestTokenCodeIsSingleUse(t *testing.T) {
	t.Parallel()
	s := fakestrava.New(t, realID, realSecret)
	code := codeFor(t, s)

	form := url.Values{
		"client_id":     {realID},
		"client_secret": {realSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
	}
	first := postForm(t, s, "/api/v3/oauth/token", form, nil)
	decode(t, first, nil)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first exchange status = %d, want 200", first.StatusCode)
	}

	second := postForm(t, s, "/api/v3/oauth/token", form, nil)
	var f faultBody
	decode(t, second, &f)
	if second.StatusCode != http.StatusBadRequest {
		t.Errorf("second exchange status = %d, want 400", second.StatusCode)
	}
	if len(f.Errors) != 1 || f.Errors[0].Resource != "AuthorizationCode" || f.Errors[0].Field != "code" {
		t.Errorf("fault = %+v, want AuthorizationCode/code/invalid", f)
	}
	if n := s.TokenRequests(); n != 2 {
		t.Errorf("TokenRequests = %d, want 2", n)
	}
}

func TestTokenCredentialFaults(t *testing.T) {
	t.Parallel()
	s := fakestrava.New(t, realID, realSecret)
	code := codeFor(t, s)

	// Real Strava is asymmetric here, and the fake must be too: an unknown
	// client_id is 400 "Bad Request" naming the field, while a known client_id
	// with a wrong secret is 401 "Authorization Error" naming none. Verified
	// live against a real application id; see docs/STRAVA-CONTRACT.md.
	tests := []struct {
		name    string
		form    url.Values
		status  int
		message string
		field   string
	}{
		{
			"wrong client_id",
			url.Values{"client_id": {"90001"}, "client_secret": {realSecret}, "code": {code}, "grant_type": {"authorization_code"}},
			http.StatusBadRequest, "Bad Request", "client_id",
		},
		{
			"wrong client_secret",
			url.Values{"client_id": {realID}, "client_secret": {"virtual-secret"}, "code": {code}, "grant_type": {"authorization_code"}},
			http.StatusUnauthorized, "Authorization Error", "",
		},
		{
			"unknown grant_type",
			url.Values{"client_id": {realID}, "client_secret": {realSecret}, "grant_type": {"password"}},
			http.StatusBadRequest, "Bad Request", "grant_type",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := postForm(t, s, "/oauth/token", tc.form, nil)
			var f faultBody
			decode(t, resp, &f)
			if resp.StatusCode != tc.status {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			if f.Message != tc.message {
				t.Errorf("message = %q, want %q", f.Message, tc.message)
			}
			if len(f.Errors) != 1 || f.Errors[0].Resource != "Application" || f.Errors[0].Field != tc.field {
				t.Errorf("fault = %+v, want Application/%q/invalid", f, tc.field)
			}
		})
	}
}

func TestTokenAcceptsQueryStringParameters(t *testing.T) {
	t.Parallel()
	s := fakestrava.New(t, realID, realSecret)
	code := codeFor(t, s)

	q := url.Values{
		"client_id":     {realID},
		"client_secret": {realSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
	}
	resp, err := noRedirectClient().Post(s.URL+"/oauth/token?"+q.Encode(), "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	var tok tokenBody
	decode(t, resp, &tok)
	if resp.StatusCode != http.StatusOK || tok.AccessToken == "" {
		t.Fatalf("status = %d, token = %+v; want a 200 with tokens", resp.StatusCode, tok)
	}
}

func TestRefreshGrant(t *testing.T) {
	t.Parallel()

	exchange := func(t *testing.T, s *fakestrava.Server) tokenBody {
		t.Helper()
		resp := postForm(t, s, "/api/v3/oauth/token", url.Values{
			"client_id":     {realID},
			"client_secret": {realSecret},
			"code":          {codeFor(t, s)},
			"grant_type":    {"authorization_code"},
		}, nil)
		var tok tokenBody
		decode(t, resp, &tok)
		return tok
	}
	refresh := func(t *testing.T, s *fakestrava.Server, rt string) (*http.Response, tokenBody) {
		t.Helper()
		resp := postForm(t, s, "/oauth/token", url.Values{
			"client_id":     {realID},
			"client_secret": {realSecret},
			"grant_type":    {"refresh_token"},
			"refresh_token": {rt},
		}, nil)
		var tok tokenBody
		body := decode(t, resp, &tok)
		if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "athlete") {
			t.Errorf("refresh response carries an athlete object: %s", body)
		}
		return resp, tok
	}

	t.Run("stable refresh token", func(t *testing.T) {
		s := fakestrava.New(t, realID, realSecret)
		first := exchange(t, s)
		resp, tok := refresh(t, s, first.RefreshToken)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if tok.RefreshToken != first.RefreshToken {
			t.Errorf("refresh_token = %q, want it unchanged (%q)", tok.RefreshToken, first.RefreshToken)
		}
		if tok.AccessToken == first.AccessToken {
			t.Error("access_token was not renewed")
		}
		// Still usable a second time.
		if resp, _ := refresh(t, s, first.RefreshToken); resp.StatusCode != http.StatusOK {
			t.Errorf("second refresh status = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("rotating refresh token", func(t *testing.T) {
		s := fakestrava.New(t, realID, realSecret)
		s.SetRotateRefresh(true)
		first := exchange(t, s)
		resp, tok := refresh(t, s, first.RefreshToken)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if tok.RefreshToken == first.RefreshToken {
			t.Error("refresh_token was not rotated")
		}
		// The old one is dead, the new one works.
		if resp, _ := refresh(t, s, first.RefreshToken); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("reusing the rotated-out token: status = %d, want 400", resp.StatusCode)
		}
		if resp, _ := refresh(t, s, tok.RefreshToken); resp.StatusCode != http.StatusOK {
			t.Errorf("using the rotated-in token: status = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("unknown refresh token", func(t *testing.T) {
		s := fakestrava.New(t, realID, realSecret)
		resp := postForm(t, s, "/oauth/token", url.Values{
			"client_id":     {realID},
			"client_secret": {realSecret},
			"grant_type":    {"refresh_token"},
			"refresh_token": {"nope"},
		}, nil)
		var f faultBody
		decode(t, resp, &f)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
		if len(f.Errors) != 1 || f.Errors[0].Resource != "RefreshToken" {
			t.Errorf("fault = %+v, want RefreshToken/refresh_token/invalid", f)
		}
	})
}

func TestSetAthleteJSON(t *testing.T) {
	t.Parallel()
	s := fakestrava.New(t, realID, realSecret)
	s.SetAthleteJSON([]byte(`{"id":7,"undocumented_field":"survives"}`))

	resp := postForm(t, s, "/api/v3/oauth/token", url.Values{
		"client_id":     {realID},
		"client_secret": {realSecret},
		"code":          {codeFor(t, s)},
		"grant_type":    {"authorization_code"},
	}, nil)
	body := decode(t, resp, nil)
	if !strings.Contains(string(body), `"undocumented_field":"survives"`) {
		t.Errorf("body = %s, want the custom athlete verbatim", body)
	}
}

func TestDeauthorize(t *testing.T) {
	t.Parallel()
	s := fakestrava.New(t, realID, realSecret)

	t.Run("form field", func(t *testing.T) {
		resp := postForm(t, s, "/oauth/deauthorize", url.Values{"access_token": {"tok-1"}}, nil)
		var got struct {
			AccessToken string `json:"access_token"`
		}
		decode(t, resp, &got)
		if resp.StatusCode != http.StatusOK || got.AccessToken != "tok-1" {
			t.Errorf("status = %d, body = %+v; want 200 echoing tok-1", resp.StatusCode, got)
		}
	})

	t.Run("bearer header", func(t *testing.T) {
		resp := postForm(t, s, "/oauth/deauthorize", nil, func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer tok-2")
		})
		var got struct {
			AccessToken string `json:"access_token"`
		}
		decode(t, resp, &got)
		if resp.StatusCode != http.StatusOK || got.AccessToken != "tok-2" {
			t.Errorf("status = %d, body = %+v; want 200 echoing tok-2", resp.StatusCode, got)
		}
		if got := s.LastAuthHeader(); got != "Bearer tok-2" {
			t.Errorf("LastAuthHeader = %q, want %q", got, "Bearer tok-2")
		}
	})

	t.Run("no token", func(t *testing.T) {
		resp := postForm(t, s, "/oauth/deauthorize", nil, nil)
		var f faultBody
		decode(t, resp, &f)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
		if f.Message != "Authorization Error" {
			t.Errorf("message = %q, want Authorization Error", f.Message)
		}
	})
}

func TestRevoke(t *testing.T) {
	t.Parallel()
	s := fakestrava.New(t, realID, realSecret)

	t.Run("success is 200 empty", func(t *testing.T) {
		resp := postForm(t, s, "/oauth/revoke", url.Values{
			"token":           {"whatever"},
			"token_type_hint": {"refresh_token"},
		}, func(r *http.Request) { r.SetBasicAuth(realID, realSecret) })
		body := decode(t, resp, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		if len(body) != 0 {
			t.Errorf("body = %q, want empty", body)
		}
	})

	t.Run("missing token is 400", func(t *testing.T) {
		resp := postForm(t, s, "/oauth/revoke", nil, func(r *http.Request) { r.SetBasicAuth(realID, realSecret) })
		decode(t, resp, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})

	badCreds := []struct {
		name string
		set  func(*http.Request)
	}{
		{"no basic auth", nil},
		{"wrong id", func(r *http.Request) { r.SetBasicAuth("90001", realSecret) }},
		{"wrong secret", func(r *http.Request) { r.SetBasicAuth(realID, "virtual-secret") }},
	}
	for _, tc := range badCreds {
		t.Run(tc.name, func(t *testing.T) {
			resp := postForm(t, s, "/oauth/revoke", url.Values{"token": {"t"}}, tc.set)
			var f faultBody
			decode(t, resp, &f)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", resp.StatusCode)
			}
			if f.Message != "Authorization Error" {
				t.Errorf("message = %q, want Authorization Error", f.Message)
			}
		})
	}
}

func TestAPIEcho(t *testing.T) {
	t.Parallel()
	s := fakestrava.New(t, realID, realSecret)

	req, err := http.NewRequest(http.MethodGet, s.URL+fakestrava.PathEcho+"?per_page=2", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer access-token-abc")
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	var echo fakestrava.Echo
	decode(t, resp, &echo)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if echo.Method != http.MethodGet || echo.Path != fakestrava.PathEcho {
		t.Errorf("echo = %+v, want GET %s", echo, fakestrava.PathEcho)
	}
	if echo.RawQuery != "per_page=2" {
		t.Errorf("raw_query = %q, want per_page=2", echo.RawQuery)
	}
	if got := echo.Headers["Authorization"]; len(got) != 1 || got[0] != "Bearer access-token-abc" {
		t.Errorf("echoed Authorization = %v, want the Bearer token verbatim", got)
	}
	// Rate-limit headers, in Strava's own casing, on every /api/v3 response.
	for name, want := range map[string]string{
		"X-RateLimit-Limit":     "600,30000",
		"X-RateLimit-Usage":     "314,27536",
		"X-ReadRateLimit-Limit": "300,15000",
		"X-ReadRateLimit-Usage": "50,100",
	} {
		if got := resp.Header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	rec, ok := s.LastRequest()
	if !ok {
		t.Fatal("no request recorded")
	}
	if rec.Path != fakestrava.PathEcho || rec.Method != http.MethodGet {
		t.Errorf("recorded = %s %s, want GET %s", rec.Method, rec.Path, fakestrava.PathEcho)
	}
	if got := rec.Form.Get("per_page"); got != "2" {
		t.Errorf("recorded form per_page = %q, want 2", got)
	}
	if got := s.LastAuthHeader(); got != "Bearer access-token-abc" {
		t.Errorf("LastAuthHeader = %q", got)
	}
	if got := s.LastRequestHeaders().Get("Authorization"); got != "Bearer access-token-abc" {
		t.Errorf("LastRequestHeaders Authorization = %q", got)
	}
}

func TestAPIEchoRecordsPostedForm(t *testing.T) {
	t.Parallel()
	s := fakestrava.New(t, realID, realSecret)

	resp := postForm(t, s, fakestrava.PathEcho, url.Values{"name": {"Morning Run"}}, nil)
	var echo fakestrava.Echo
	decode(t, resp, &echo)
	if got := echo.Form["name"]; len(got) != 1 || got[0] != "Morning Run" {
		t.Errorf("echoed form = %v", echo.Form)
	}
	if echo.Body != "name=Morning+Run" {
		t.Errorf("echoed body = %q", echo.Body)
	}
	rec, _ := s.LastRequest()
	if string(rec.Body) != "name=Morning+Run" {
		t.Errorf("recorded body = %q", rec.Body)
	}
}

func TestAPICustomRateLimitHeaders(t *testing.T) {
	t.Parallel()
	s := fakestrava.New(t, realID, realSecret)
	// Lowercase spelling: the docs render the casing inconsistently, and the
	// proxy must not normalise it either way.
	s.SetRateLimitHeaders(http.Header{"x-ratelimit-usage": {"1,1"}})

	resp, err := noRedirectClient().Get(s.URL + fakestrava.PathEcho)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	decode(t, resp, nil)
	if got := resp.Header.Get("X-RateLimit-Usage"); got != "1,1" {
		t.Errorf("x-ratelimit-usage = %q, want 1,1", got)
	}
	if resp.Header.Get("X-RateLimit-Limit") != "" {
		t.Error("default headers survived SetRateLimitHeaders")
	}
}

func TestAPIGzip(t *testing.T) {
	t.Parallel()
	s := fakestrava.New(t, realID, realSecret)

	// A manual round trip: the default Transport would decompress
	// transparently and hide the encoding.
	req, err := http.NewRequest(http.MethodGet, s.URL+fakestrava.PathGzip, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer zr.Close()
	var echo fakestrava.Echo
	if err := json.NewDecoder(zr).Decode(&echo); err != nil {
		t.Fatalf("decoding gzip body: %v", err)
	}
	if echo.Path != fakestrava.PathGzip {
		t.Errorf("echo.Path = %q, want %q", echo.Path, fakestrava.PathGzip)
	}
}

func TestAPIStream(t *testing.T) {
	t.Parallel()
	s := fakestrava.New(t, realID, realSecret)
	s.SetStream(4, time.Millisecond)

	resp, err := noRedirectClient().Get(s.URL + fakestrava.PathStream)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.ContentLength != -1 {
		t.Errorf("ContentLength = %d, want -1 (chunked)", resp.ContentLength)
	}
	if len(resp.TransferEncoding) == 0 || resp.TransferEncoding[0] != "chunked" {
		t.Errorf("TransferEncoding = %v, want [chunked]", resp.TransferEncoding)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading stream: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d chunks (%q), want 4", len(lines), body)
	}
	if lines[0] != `{"chunk":0}` || lines[3] != `{"chunk":3}` {
		t.Errorf("chunks = %q", lines)
	}
}

func TestAPIFaultPaths(t *testing.T) {
	t.Parallel()
	s := fakestrava.New(t, realID, realSecret)

	tests := []struct {
		path     string
		status   int
		message  string
		resource string
	}{
		{fakestrava.PathRateLimited, http.StatusTooManyRequests, "Rate Limit Exceeded", "Application"},
		{fakestrava.PathUnauthorized, http.StatusUnauthorized, "Authorization Error", "Athlete"},
		{"/nowhere", http.StatusNotFound, "Resource Not Found", "Resource"},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := noRedirectClient().Get(s.URL + tc.path)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			var f faultBody
			decode(t, resp, &f)
			if resp.StatusCode != tc.status {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			if f.Message != tc.message {
				t.Errorf("message = %q, want %q", f.Message, tc.message)
			}
			if len(f.Errors) != 1 || f.Errors[0].Resource != tc.resource {
				t.Errorf("errors = %+v, want resource %q", f.Errors, tc.resource)
			}
		})
	}
}

func TestHangTripsClientTimeout(t *testing.T) {
	t.Parallel()
	s := fakestrava.New(t, realID, realSecret)
	s.SetHang(300 * time.Millisecond)

	client := &http.Client{Timeout: 30 * time.Millisecond}
	_, err := client.Get(s.URL + fakestrava.PathEcho)
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	var timeoutErr interface{ Timeout() bool }
	if !errors.As(err, &timeoutErr) || !timeoutErr.Timeout() {
		t.Fatalf("err = %v, want a timeout", err)
	}
	// The request still reached the fake and was recorded.
	if len(s.RequestsTo(fakestrava.PathEcho)) != 1 {
		t.Errorf("recorded %d requests, want 1", len(s.RequestsTo(fakestrava.PathEcho)))
	}
	s.SetHang(0)
}

func TestRecordingAndReset(t *testing.T) {
	t.Parallel()
	s := fakestrava.New(t, realID, realSecret)

	code := codeFor(t, s)
	resp := postForm(t, s, "/api/v3/oauth/token", url.Values{
		"client_id":     {realID},
		"client_secret": {realSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
	}, func(r *http.Request) { r.Header.Set("Accept", "application/json") })
	decode(t, resp, nil)

	reqs := s.Requests()
	if len(reqs) != 2 {
		t.Fatalf("recorded %d requests, want 2", len(reqs))
	}
	if reqs[0].Path != "/oauth/authorize" || reqs[1].Path != "/api/v3/oauth/token" {
		t.Errorf("recorded paths = %q, %q", reqs[0].Path, reqs[1].Path)
	}
	tokenReq := reqs[1]
	if got := tokenReq.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := tokenReq.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept = %q", got)
	}
	if got := tokenReq.Form.Get("client_secret"); got != realSecret {
		t.Errorf("recorded client_secret = %q, want the real one", got)
	}
	if !strings.Contains(string(tokenReq.Body), "grant_type=authorization_code") {
		t.Errorf("recorded body = %q", tokenReq.Body)
	}
	// Mutating the snapshot cannot corrupt the server's copy.
	reqs[0].Form.Set("client_id", "tampered")
	if got := s.Requests()[0].Form.Get("client_id"); got != realID {
		t.Errorf("snapshot aliases server state: %q", got)
	}

	s.Reset()
	if got := s.Requests(); len(got) != 0 {
		t.Errorf("Requests after Reset = %d, want 0", len(got))
	}
	if got := s.TokenRequests(); got != 0 {
		t.Errorf("TokenRequests after Reset = %d, want 0", got)
	}
	if got := s.LastAuthHeader(); got != "" {
		t.Errorf("LastAuthHeader after Reset = %q", got)
	}
	if s.LastRequestHeaders() != nil {
		t.Error("LastRequestHeaders after Reset is not nil")
	}
}

func TestConcurrentUse(t *testing.T) {
	t.Parallel()
	s := fakestrava.New(t, realID, realSecret)

	const n = 16
	done := make(chan struct{})
	for i := range n {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			if i%2 == 0 {
				s.SetGrantedScope("read")
				s.SetRotateRefresh(i%4 == 0)
			}
			resp, err := noRedirectClient().Get(s.URL + fakestrava.PathEcho)
			if err != nil {
				t.Errorf("GET: %v", err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			_ = s.Requests()
			_ = s.TokenRequests()
			_ = s.LastRequestHeaders()
		}(i)
	}
	for range n {
		<-done
	}
	if got := len(s.RequestsTo(fakestrava.PathEcho)); got != n {
		t.Errorf("recorded %d requests, want %d", got, n)
	}
}
