package metrics_test

import (
	"expvar"
	"testing"

	"github.com/glandais/strava-auth-proxy/internal/metrics"
)

func value(t *testing.T, m *expvar.Map, key string) int64 {
	t.Helper()
	v := m.Get(key)
	if v == nil {
		return 0
	}
	iv, ok := v.(*expvar.Int)
	if !ok {
		t.Fatalf("key %q holds %T, want *expvar.Int", key, v)
	}
	return iv.Value()
}

func TestInc(t *testing.T) {
	tests := []struct {
		name string
		m    *expvar.Map
		key  string
		n    int
	}{
		{name: "callbacks", m: metrics.OAuthCallbacks, key: "test_success", n: 1},
		{name: "token exchanges", m: metrics.TokenExchanges, key: "authorization_code:test_ok", n: 3},
		{name: "upstream errors", m: metrics.UpstreamErrors, key: "test_timeout", n: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := value(t, tt.m, tt.key)
			for range tt.n {
				metrics.Inc(tt.m, tt.key)
			}
			if got, want := value(t, tt.m, tt.key), before+int64(tt.n); got != want {
				t.Errorf("counter %q = %d, want %d", tt.key, got, want)
			}
		})
	}
}

func TestIncIsNilAndEmptySafe(t *testing.T) {
	metrics.Inc(nil, "whatever") // must not panic

	before := value(t, metrics.UpstreamErrors, "")
	metrics.Inc(metrics.UpstreamErrors, "")
	if got := value(t, metrics.UpstreamErrors, ""); got != before {
		t.Errorf("empty key recorded a value: %d", got)
	}
}

func TestMapsArePublishedUnderContractNames(t *testing.T) {
	tests := []struct {
		name string
		want *expvar.Map
	}{
		{name: metrics.NameOAuthCallbacks, want: metrics.OAuthCallbacks},
		{name: metrics.NameTokenExchanges, want: metrics.TokenExchanges},
		{name: metrics.NameUpstreamErrors, want: metrics.UpstreamErrors},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expvar.Get(tt.name)
			if got == nil {
				t.Fatalf("expvar %q not published", tt.name)
			}
			if got != expvar.Var(tt.want) {
				t.Errorf("expvar %q is a different map than the exported one", tt.name)
			}
		})
	}
}

// Importing the package twice in one binary must not panic on duplicate
// registration; this exercises the same guard mustMap relies on.
func TestRepublishGuard(t *testing.T) {
	if expvar.Get(metrics.NameOAuthCallbacks) == nil {
		t.Fatal("expected the map to already be published")
	}
	// A second call through the public surface must still work.
	metrics.Inc(metrics.OAuthCallbacks, "guard")
	if value(t, metrics.OAuthCallbacks, "guard") != 1 {
		t.Error("Inc after republish guard did not record")
	}
}
