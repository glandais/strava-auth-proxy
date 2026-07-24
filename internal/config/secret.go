package config

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strconv"
)

// Redacted is the placeholder rendered by every textual or structured
// representation of a [Secret].
const Redacted = "[REDACTED]"

// Secret wraps a plaintext secret so that it cannot leak through fmt verbs,
// encoding/json or log/slog. The only way to obtain the underlying value is
// [Secret.Reveal].
//
// The zero Secret holds the empty string.
type Secret struct {
	v string
}

// NewSecret wraps s in a redacting Secret.
func NewSecret(s string) Secret { return Secret{v: s} }

// Reveal returns the plaintext secret. It is the ONLY accessor that yields the
// real value; call sites are deliberately easy to grep for.
func (s Secret) Reveal() string { return s.v }

// IsZero reports whether the secret is empty.
func (s Secret) IsZero() bool { return s.v == "" }

// String implements fmt.Stringer and always returns [Redacted].
func (s Secret) String() string { return Redacted }

// GoString implements fmt.GoStringer and always returns [Redacted].
func (s Secret) GoString() string { return Redacted }

// Format implements fmt.Formatter so that every verb — including %v, %s, %#v
// and %+v — renders [Redacted] instead of the plaintext value.
func (s Secret) Format(f fmt.State, verb rune) {
	if verb == 'q' {
		io.WriteString(f, strconv.Quote(Redacted)) //nolint:errcheck // fmt.State swallows errors
		return
	}
	io.WriteString(f, Redacted) //nolint:errcheck // fmt.State swallows errors
}

// MarshalJSON implements json.Marshaler and always emits the redacted string.
func (s Secret) MarshalJSON() ([]byte, error) { return json.Marshal(Redacted) }

// UnmarshalJSON implements json.Unmarshaler so secret-bearing configuration
// fields can deserialize directly into a Secret.
func (s *Secret) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return fmt.Errorf("config: secret must be a JSON string: %w", err)
	}
	s.v = str
	return nil
}

// LogValue implements slog.LogValuer and always returns the redacted string.
func (s Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }

// Compile-time proof that every leak-prone interface is implemented.
var (
	_ fmt.Stringer   = Secret{}
	_ fmt.GoStringer = Secret{}
	_ fmt.Formatter  = Secret{}
	_ json.Marshaler = Secret{}
	_ slog.LogValuer = Secret{}
)
