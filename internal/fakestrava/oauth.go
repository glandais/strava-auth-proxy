package fakestrava

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Grant types the fake understands.
const (
	grantAuthorizationCode = "authorization_code"
	grantRefreshToken      = "refresh_token"
)

// handleAuthorize serves GET /oauth/authorize and GET /oauth/mobile/authorize.
//
// It validates only the real client_id and the presence of a redirect_uri,
// then redirects straight back — there is no consent page to render. Success
// carries a freshly minted single-use code plus the granted scope; the
// AuthorizeError knob replaces both with error=<value>. The state parameter is
// echoed unchanged, and only when it was sent.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	if q.Get("client_id") != s.realClientID {
		writeFault(w, http.StatusBadRequest, "Bad Request", faultError{"Application", "client_id", "invalid"})
		return
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		writeFault(w, http.StatusBadRequest, "Bad Request", faultError{"Application", "redirect_uri", "invalid"})
		return
	}
	dst, err := url.Parse(redirectURI)
	if err != nil {
		writeFault(w, http.StatusBadRequest, "Bad Request", faultError{"Application", "redirect_uri", "invalid"})
		return
	}

	out := dst.Query()
	state, hasState := q["state"]
	if hasState && len(state) > 0 {
		out.Set("state", state[0])
	}

	s.mu.Lock()
	authErr := s.authorizeError
	granted := s.grantedScope
	if granted == "" {
		granted = normalizeScope(q.Get("scope"))
	}
	var code string
	if authErr == "" {
		s.seq++
		code = fmt.Sprintf("fakecode%d%s", s.seq, randomSuffix())
		s.codes[code] = false
	}
	s.mu.Unlock()

	if authErr != "" {
		out.Set("error", authErr)
	} else {
		out.Set("code", code)
		if granted != "" {
			out.Set("scope", granted)
		}
	}

	dst.RawQuery = out.Encode()
	http.Redirect(w, r, dst.String(), http.StatusFound)
}

// tokenResponse is the documented token payload. athlete is omitted on
// anything but the authorization_code grant.
type tokenResponse struct {
	TokenType    string          `json:"token_type"`
	ExpiresAt    int64           `json:"expires_at"`
	ExpiresIn    int             `json:"expires_in"`
	RefreshToken string          `json:"refresh_token"`
	AccessToken  string          `json:"access_token"`
	Athlete      json.RawMessage `json:"athlete,omitempty"`
}

// handleToken serves POST /api/v3/oauth/token and POST /oauth/token.
//
// Both routes accept both grant types. Parameters are read from the merged
// form (body and query string), as the live service does. Authorization codes
// are single-use: the second presentation of a code yields the canonical
// AuthorizationCode fault.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.tokenRequests++
	s.mu.Unlock()

	if r.Form.Get("client_id") != s.realClientID {
		writeFault(w, http.StatusBadRequest, "Bad Request", faultError{"Application", "client_id", "invalid"})
		return
	}
	if r.Form.Get("client_secret") != s.realClientSecret {
		writeFault(w, http.StatusBadRequest, "Bad Request", faultError{"Application", "client_secret", "invalid"})
		return
	}

	switch r.Form.Get("grant_type") {
	case grantAuthorizationCode:
		s.exchangeCode(w, r.Form.Get("code"))
	case grantRefreshToken:
		s.refresh(w, r.Form.Get("refresh_token"))
	default:
		writeFault(w, http.StatusBadRequest, "Bad Request", faultError{"Application", "grant_type", "invalid"})
	}
}

// exchangeCode burns a single-use authorization code and issues a full token
// set, athlete object included.
func (s *Server) exchangeCode(w http.ResponseWriter, code string) {
	s.mu.Lock()
	used, ok := s.codes[code]
	if !ok || used {
		s.mu.Unlock()
		writeFault(w, http.StatusBadRequest, "Bad Request", faultError{"AuthorizationCode", "code", "invalid"})
		return
	}
	s.codes[code] = true
	access, refresh := s.issueTokensLocked()
	athlete := s.athlete
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, tokenResponse{
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(accessTokenTTL * time.Second).Unix(),
		ExpiresIn:    accessTokenTTL,
		RefreshToken: refresh,
		AccessToken:  access,
		Athlete:      athlete,
	})
}

// refresh exchanges a previously issued refresh token. The response never
// carries an athlete object. With RotateRefresh set, the presented token is
// invalidated and a new one is returned.
func (s *Server) refresh(w http.ResponseWriter, presented string) {
	s.mu.Lock()
	if presented == "" || !s.refreshTokens[presented] {
		s.mu.Unlock()
		writeFault(w, http.StatusBadRequest, "Bad Request", faultError{"RefreshToken", "refresh_token", "invalid"})
		return
	}
	access, refresh := s.issueTokensLocked()
	if s.rotateRefresh {
		delete(s.refreshTokens, presented)
	} else {
		delete(s.refreshTokens, refresh)
		refresh = presented
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, tokenResponse{
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(accessTokenTTL * time.Second).Unix(),
		ExpiresIn:    accessTokenTTL,
		RefreshToken: refresh,
		AccessToken:  access,
	})
}

// issueTokensLocked mints a fresh access/refresh pair and registers the
// refresh token as valid. The caller must hold s.mu.
func (s *Server) issueTokensLocked() (access, refresh string) {
	s.seq++
	n := s.seq
	access = fmt.Sprintf("fakeaccess%d%s", n, randomSuffix())
	refresh = fmt.Sprintf("fakerefresh%d%s", n, randomSuffix())
	s.refreshTokens[refresh] = true
	return access, refresh
}

// deauthorizeResponse is the legacy endpoint's echo body.
type deauthorizeResponse struct {
	AccessToken string `json:"access_token"`
}

// handleDeauthorize serves POST /oauth/deauthorize, the legacy endpoint.
//
// It authenticates with the athlete's access token, taken from the
// access_token form field or from an Authorization: Bearer header, and echoes
// it back. No client credentials are involved, which is exactly why the proxy
// treats this route as a pure pass-through. A missing token yields the
// canonical 401 fault.
func (s *Server) handleDeauthorize(w http.ResponseWriter, r *http.Request) {
	token := r.Form.Get("access_token")
	if token == "" {
		if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "Bearer ") {
			token = strings.TrimSpace(strings.TrimPrefix(v, "Bearer "))
		}
	}
	if token == "" {
		writeFault(w, http.StatusUnauthorized, "Authorization Error", faultError{"Athlete", "access_token", "invalid"})
		return
	}
	writeJSON(w, http.StatusOK, deauthorizeResponse{AccessToken: token})
}

// handleRevoke serves POST /oauth/revoke, the current RFC 7009-shaped
// endpoint: HTTP Basic with the real application credentials, a required token
// field, and a 200 with an empty body on success — including for tokens the
// server has never heard of.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	id, secret, ok := r.BasicAuth()
	if !ok || id != s.realClientID || secret != s.realClientSecret {
		writeFault(w, http.StatusUnauthorized, "Authorization Error", faultError{"Application", "client_id", "invalid"})
		return
	}
	token := r.Form.Get("token")
	if token == "" {
		writeFault(w, http.StatusBadRequest, "Bad Request", faultError{"Application", "token", "invalid"})
		return
	}

	s.mu.Lock()
	delete(s.refreshTokens, token)
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

// normalizeScope converts a requested scope list to the comma-delimited form
// Strava uses in the redirect callback. Requests may use either delimiter.
func normalizeScope(requested string) string {
	fields := strings.FieldsFunc(requested, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	return strings.Join(fields, ",")
}

// randomSuffix returns a short unguessable string, so codes and tokens minted
// by different runs never collide in a test's expectations.
func randomSuffix() string {
	var b [9]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "x"
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// faultError is one entry of Strava's Fault.errors array.
type faultError struct {
	Resource string `json:"resource"`
	Field    string `json:"field"`
	Code     string `json:"code"`
}

// fault is Strava's error envelope.
type fault struct {
	Message string       `json:"message"`
	Errors  []faultError `json:"errors"`
}

// writeFault renders a Fault body with the given status.
func writeFault(w http.ResponseWriter, status int, message string, errs ...faultError) {
	if errs == nil {
		errs = []faultError{}
	}
	writeJSON(w, status, fault{Message: message, Errors: errs})
}

// writeJSON marshals v and writes it with an accurate Content-Length, so
// relayed responses have a length the proxy can copy through.
func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "fakestrava: marshal failed", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
