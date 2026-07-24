// Package fault renders Strava-shaped error bodies.
//
// Every proxy-minted error response goes through this package so that the
// wire format stays byte-for-byte identical to what real Strava emits. The
// Fault model is documented in docs/STRAVA-CONTRACT.md §7:
//
//	{"message":"...","errors":[{"resource":"...","field":"...","code":"..."}]}
//
// Bodies are written as compact JSON with no trailing newline, which is what
// the contract reference documents and what Strava returns on the wire.
package fault

import (
	"encoding/json"
	"html"
	"net/http"
	"strconv"
)

// ContentTypeJSON is the media type used for every Fault body.
const ContentTypeJSON = "application/json; charset=utf-8"

// ContentTypeHTML is the media type used for browser-facing error pages.
const ContentTypeHTML = "text/html; charset=utf-8"

// Error is a single entry of a Fault's errors array.
type Error struct {
	Resource string `json:"resource"`
	Field    string `json:"field"`
	Code     string `json:"code"`
}

// Fault is Strava's canonical error envelope.
type Fault struct {
	Message string  `json:"message"`
	Errors  []Error `json:"errors"`
}

// fallbackBody is emitted only if marshalling a Fault somehow fails. Fault is
// composed exclusively of strings, so this is unreachable in practice; it
// exists so Write can never panic or emit an empty body in a request path.
const fallbackBody = `{"message":"Bad Request","errors":[]}`

// Write emits f as a compact JSON body with the given status code.
//
// It sets Content-Type and Content-Length before writing the header, so the
// response is fully determined regardless of chunking heuristics. A nil
// Errors slice is normalised to an empty array (never JSON null).
func Write(w http.ResponseWriter, status int, f Fault) {
	if f.Errors == nil {
		f.Errors = []Error{}
	}
	body, err := json.Marshal(f)
	if err != nil {
		body = []byte(fallbackBody)
	}
	h := w.Header()
	h.Set("Content-Type", ContentTypeJSON)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// WriteInvalidClientID reports an unknown virtual client_id on a token
// endpoint: 400 with resource Application, field client_id.
func WriteInvalidClientID(w http.ResponseWriter) {
	Write(w, http.StatusBadRequest, Fault{
		Message: "Bad Request",
		Errors:  []Error{{Resource: "Application", Field: "client_id", Code: "invalid"}},
	})
}

// WriteInvalidClientSecret reports a wrong virtual client_secret on a token
// endpoint: 400 with resource Application, field client_secret.
func WriteInvalidClientSecret(w http.ResponseWriter) {
	Write(w, http.StatusBadRequest, Fault{
		Message: "Bad Request",
		Errors:  []Error{{Resource: "Application", Field: "client_secret", Code: "invalid"}},
	})
}

// WriteInvalidCode reports a malformed, expired, or foreign-client wrapped
// authorization code: 400 with resource AuthorizationCode, field code.
func WriteInvalidCode(w http.ResponseWriter) {
	Write(w, http.StatusBadRequest, Fault{
		Message: "Bad Request",
		Errors:  []Error{{Resource: "AuthorizationCode", Field: "code", Code: "invalid"}},
	})
}

// WriteUnauthorized reports bad HTTP Basic credentials on /oauth/revoke:
// 401 with Strava's "Authorization Error" message.
func WriteUnauthorized(w http.ResponseWriter) {
	Write(w, http.StatusUnauthorized, Fault{
		Message: "Authorization Error",
		Errors:  []Error{{Resource: "Application", Field: "client_id", Code: "invalid"}},
	})
}

// WriteUpstreamUnavailable reports that Strava could not be reached:
// 502 with resource Upstream, field strava, code unavailable.
func WriteUpstreamUnavailable(w http.ResponseWriter) {
	Write(w, http.StatusBadGateway, Fault{
		Message: "Bad Gateway",
		Errors:  []Error{{Resource: "Upstream", Field: "strava", Code: "unavailable"}},
	})
}

// WriteUpstreamTimeout reports that the call to Strava exceeded its deadline:
// 504 with resource Upstream, field strava, code timeout.
func WriteUpstreamTimeout(w http.ResponseWriter) {
	Write(w, http.StatusGatewayTimeout, Fault{
		Message: "Gateway Timeout",
		Errors:  []Error{{Resource: "Upstream", Field: "strava", Code: "timeout"}},
	})
}

// defaultDetail is used when a caller passes an empty detail string.
const defaultDetail = "The request could not be processed."

// WriteBadRequestPage renders the minimal browser-facing 400 page used on the
// authorize and callback paths, where redirecting would be unsafe.
//
// detail is HTML-escaped before interpolation, so it can never inject markup.
// Callers must nonetheless pass a short, static description: the page is
// deliberately free of any echo of the request query string, so authorization
// codes, state envelopes and secrets can never be reflected back to the
// browser or captured by a screenshot/paste.
func WriteBadRequestPage(w http.ResponseWriter, detail string) {
	if detail == "" {
		detail = defaultDetail
	}
	body := badRequestPage(detail)
	h := w.Header()
	h.Set("Content-Type", ContentTypeHTML)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write(body)
}

func badRequestPage(detail string) []byte {
	const (
		prefix = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>400 Bad Request</title>
</head>
<body>
<h1>400 Bad Request</h1>
<p>`
		suffix = `</p>
</body>
</html>
`
	)
	escaped := html.EscapeString(detail)
	b := make([]byte, 0, len(prefix)+len(escaped)+len(suffix))
	b = append(b, prefix...)
	b = append(b, escaped...)
	b = append(b, suffix...)
	return b
}
