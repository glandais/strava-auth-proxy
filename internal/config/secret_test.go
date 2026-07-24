package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const plaintextSecret = "super-secret-value-do-not-leak"

func TestSecretReveal(t *testing.T) {
	s := NewSecret(plaintextSecret)
	if got := s.Reveal(); got != plaintextSecret {
		t.Fatalf("Reveal() = %q, want %q", got, plaintextSecret)
	}
	if !NewSecret("").IsZero() {
		t.Error("empty secret should report IsZero")
	}
	if (Secret{}).Reveal() != "" {
		t.Error("zero Secret should reveal the empty string")
	}
	if NewSecret(plaintextSecret).IsZero() {
		t.Error("non-empty secret must not report IsZero")
	}
}

func TestSecretFmtRedaction(t *testing.T) {
	s := NewSecret(plaintextSecret)
	tests := []struct {
		name   string
		format string
		arg    any
		want   string
	}{
		{"percent-v", "%v", s, Redacted},
		{"percent-s", "%s", s, Redacted},
		{"percent-d", "%d", s, Redacted},
		{"percent-goSyntax", "%#v", s, Redacted},
		{"percent-plusV", "%+v", s, Redacted},
		{"percent-q", "%q", s, `"` + Redacted + `"`},
		{"pointer-v", "%v", &s, Redacted},
		{"pointer-goSyntax", "%#v", &s, Redacted},
		{"struct-field-v", "%v", struct{ S Secret }{s}, "{" + Redacted + "}"},
		{"struct-field-plusV", "%+v", struct{ S Secret }{s}, "{S:" + Redacted + "}"},
		{"struct-field-goSyntax", "%#v", struct{ S Secret }{s}, "struct { S config.Secret }{S:" + Redacted + "}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fmt.Sprintf(tt.format, tt.arg)
			if got != tt.want {
				t.Errorf("Sprintf(%q) = %q, want %q", tt.format, got, tt.want)
			}
			if strings.Contains(got, plaintextSecret) {
				t.Errorf("Sprintf(%q) leaked the plaintext secret: %q", tt.format, got)
			}
		})
	}

	if got := s.String(); got != Redacted {
		t.Errorf("String() = %q, want %q", got, Redacted)
	}
	if got := s.GoString(); got != Redacted {
		t.Errorf("GoString() = %q, want %q", got, Redacted)
	}
}

func TestSecretJSONRedaction(t *testing.T) {
	s := NewSecret(plaintextSecret)

	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(b) != `"`+Redacted+`"` {
		t.Errorf("json.Marshal(Secret) = %s, want %q", b, Redacted)
	}

	type wrapper struct {
		Name   string `json:"name"`
		Secret Secret `json:"secret"`
	}
	b, err = json.Marshal(wrapper{Name: "n", Secret: s})
	if err != nil {
		t.Fatalf("json.Marshal(wrapper): %v", err)
	}
	if strings.Contains(string(b), plaintextSecret) {
		t.Errorf("json.Marshal leaked the plaintext secret: %s", b)
	}
	if want := `{"name":"n","secret":"` + Redacted + `"}`; string(b) != want {
		t.Errorf("json.Marshal(wrapper) = %s, want %s", b, want)
	}
}

func TestSecretUnmarshalJSON(t *testing.T) {
	var w struct {
		Secret Secret `json:"secret"`
	}
	if err := json.Unmarshal([]byte(`{"secret":"`+plaintextSecret+`"}`), &w); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if got := w.Secret.Reveal(); got != plaintextSecret {
		t.Errorf("Reveal() = %q, want %q", got, plaintextSecret)
	}
	if err := json.Unmarshal([]byte(`{"secret":42}`), &w); err == nil {
		t.Error("expected an error unmarshaling a non-string secret")
	}
}

func TestSecretSlogRedaction(t *testing.T) {
	s := NewSecret(plaintextSecret)
	for _, tc := range []struct {
		name string
		new  func(*bytes.Buffer) slog.Handler
	}{
		{"json", func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) }},
		{"text", func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(tc.new(&buf))
			logger.Info("hello", "secret", s, "ptr", &s, "group", slog.GroupValue(slog.Any("nested", s)))
			out := buf.String()
			if strings.Contains(out, plaintextSecret) {
				t.Fatalf("slog leaked the plaintext secret: %s", out)
			}
			if !strings.Contains(out, Redacted) {
				t.Fatalf("slog output does not contain %q: %s", Redacted, out)
			}
		})
	}
}

func TestConfigSlogRedaction(t *testing.T) {
	cfg := &Config{
		StravaClientID:     "12345",
		StravaClientSecret: NewSecret(plaintextSecret),
		PublicURL:          "https://proxy.example",
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("cfg", "config", cfg, "value", *cfg)
	if strings.Contains(buf.String(), plaintextSecret) {
		t.Fatalf("logging a Config leaked the Strava secret: %s", buf.String())
	}

	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		if got := fmt.Sprintf(format, cfg); strings.Contains(got, plaintextSecret) {
			t.Fatalf("Sprintf(%q, cfg) leaked the Strava secret: %s", format, got)
		}
	}
	if b, err := json.Marshal(cfg); err != nil {
		t.Fatalf("json.Marshal(cfg): %v", err)
	} else if strings.Contains(string(b), plaintextSecret) {
		t.Fatalf("json.Marshal(cfg) leaked the Strava secret: %s", b)
	}
}
