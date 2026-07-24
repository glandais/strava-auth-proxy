// Package metrics holds the proxy's expvar counters.
//
// Counters are published on the admin listener's /metrics endpoint as expvar
// JSON. Each counter is an *expvar.Map whose keys carry the label dimension,
// e.g. UpstreamErrors.Get("timeout").
package metrics

import "expvar"

// Published expvar names. They are exported so tests and the admin handler can
// look the maps up by name without importing unexported identifiers.
const (
	NameOAuthCallbacks = "oauth_callbacks_total"
	NameTokenExchanges = "token_exchanges_total"
	NameUpstreamErrors = "upstream_errors_total"
)

var (
	// OAuthCallbacks counts /oauth/callback outcomes, keyed by outcome.
	OAuthCallbacks = mustMap(NameOAuthCallbacks)
	// TokenExchanges counts token-endpoint outcomes, keyed by
	// grant_type + ":" + outcome.
	TokenExchanges = mustMap(NameTokenExchanges)
	// UpstreamErrors counts proxy-to-Strava failures, keyed by kind
	// (e.g. "unavailable", "timeout").
	UpstreamErrors = mustMap(NameUpstreamErrors)
)

// mustMap returns the *expvar.Map published under name, publishing it first if
// necessary. expvar.NewMap panics on duplicate registration, so an already
// published map of the same name is reused instead. This keeps the package
// safe to import from any test binary, and safe against a name collision with
// another package.
func mustMap(name string) *expvar.Map {
	if v := expvar.Get(name); v != nil {
		if m, ok := v.(*expvar.Map); ok {
			return m
		}
		// Something else already owns the name; fall back to an unpublished
		// map rather than panicking in package init.
		return new(expvar.Map).Init()
	}
	return expvar.NewMap(name)
}

// Inc adds one to the counter stored under key in m.
//
// It is a no-op for a nil map or an empty key, so instrumentation can never
// panic in a request path.
func Inc(m *expvar.Map, key string) {
	if m == nil || key == "" {
		return
	}
	m.Add(key, 1)
}
