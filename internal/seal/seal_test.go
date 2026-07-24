package seal

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	keyNew = Key{KID: "k2", Key: bytes.Repeat([]byte{0x2a}, 32)}
	keyOld = Key{KID: "k1", Key: bytes.Repeat([]byte{0x11}, 32)}
)

func testRing() Ring { return Ring{keyNew, keyOld} }

func fixedNow() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

const testTTL = 15 * time.Minute

// mutate replaces part i of token (parts are "."-separated) using f.
func mutate(t *testing.T, token string, i int, f func([]byte) []byte) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != numParts {
		t.Fatalf("token has %d parts, want %d", len(parts), numParts)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[i])
	if err != nil {
		t.Fatalf("decode part %d: %v", i, err)
	}
	parts[i] = base64.RawURLEncoding.EncodeToString(f(raw))
	return strings.Join(parts, ".")
}

// flipBit returns a copy of b with the lowest bit of the first byte flipped.
func flipBit(b []byte) []byte {
	out := append([]byte(nil), b...)
	if len(out) == 0 {
		return []byte{0x01}
	}
	out[0] ^= 0x01
	return out
}

func TestRoundTrip(t *testing.T) {
	now := fixedNow()
	ring := testRing()

	t.Run("state", func(t *testing.T) {
		want := StatePayload{
			CID:   "90001",
			RU:    "https://app.example/cb?x=1&y=2",
			ST:    "caller-state-éà \x00 raw",
			HasST: true,
			IAT:   now.Unix(),
			Nonce: "abc123",
		}
		token, err := ring.Seal(DomainState, want)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if got := strings.Count(token, "."); got != 2 {
			t.Fatalf("token %q has %d dots, want 2", token, got)
		}
		if kid := strings.SplitN(token, ".", 2)[0]; kid != keyNew.KID {
			t.Errorf("kid = %q, want %q (newest key)", kid, keyNew.KID)
		}
		var got StatePayload
		if err := ring.Open(DomainState, token, &got, testTTL, now); err != nil {
			t.Fatalf("Open: %v", err)
		}
		if got != want {
			t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, want)
		}
	})

	t.Run("state without caller state", func(t *testing.T) {
		want := StatePayload{CID: "90001", RU: "https://app.example/cb", IAT: now.Unix()}
		token, err := ring.Seal(DomainState, want)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		var got StatePayload
		if err := ring.Open(DomainState, token, &got, testTTL, now); err != nil {
			t.Fatalf("Open: %v", err)
		}
		if got.HasST {
			t.Errorf("HasST = true, want false")
		}
		if got != want {
			t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, want)
		}
	})

	t.Run("code", func(t *testing.T) {
		want := CodePayload{CID: "90002", SC: "b1946ac92492d2347c6235b4d2611184", IAT: now.Unix()}
		token, err := ring.Seal(DomainCode, want)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		var got CodePayload
		if err := ring.Open(DomainCode, token, &got, testTTL, now); err != nil {
			t.Fatalf("Open: %v", err)
		}
		if got != want {
			t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, want)
		}
	})
}

func TestOpenRejects(t *testing.T) {
	now := fixedNow()
	ring := testRing()

	valid := func(t *testing.T) string {
		t.Helper()
		token, err := ring.Seal(DomainState, StatePayload{CID: "90001", RU: "https://app.example/cb", IAT: now.Unix()})
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		return token
	}

	tests := []struct {
		name  string
		token func(t *testing.T) string
		want  error
	}{
		{
			name:  "payload tampered by one bit",
			token: func(t *testing.T) string { return mutate(t, valid(t), 1, flipBit) },
			want:  ErrBadMAC,
		},
		{
			name:  "mac tampered by one bit",
			token: func(t *testing.T) string { return mutate(t, valid(t), 2, flipBit) },
			want:  ErrBadMAC,
		},
		{
			name:  "mac truncated",
			token: func(t *testing.T) string { return mutate(t, valid(t), 2, func(b []byte) []byte { return b[:16] }) },
			want:  ErrBadMAC,
		},
		{
			name:  "mac empty",
			token: func(t *testing.T) string { return mutate(t, valid(t), 2, func([]byte) []byte { return nil }) },
			want:  ErrBadMAC,
		},
		{
			name: "kid swapped to another ring key",
			token: func(t *testing.T) string {
				return keyOld.KID + strings.TrimPrefix(valid(t), keyNew.KID)
			},
			want: ErrBadMAC,
		},
		{
			name: "unknown kid",
			token: func(t *testing.T) string {
				return "k99" + strings.TrimPrefix(valid(t), keyNew.KID)
			},
			want: ErrUnknownKID,
		},
		{
			name:  "empty token",
			token: func(*testing.T) string { return "" },
			want:  ErrMalformed,
		},
		{
			name:  "two parts",
			token: func(t *testing.T) string { p := strings.Split(valid(t), "."); return p[0] + "." + p[1] },
			want:  ErrMalformed,
		},
		{
			name:  "four parts",
			token: func(t *testing.T) string { return valid(t) + ".extra" },
			want:  ErrMalformed,
		},
		{
			name: "payload not base64",
			token: func(t *testing.T) string {
				p := strings.Split(valid(t), ".")
				return p[0] + ".!!!not-base64!!!." + p[2]
			},
			want: ErrMalformed,
		},
		{
			name: "mac not base64",
			token: func(t *testing.T) string {
				p := strings.Split(valid(t), ".")
				return p[0] + "." + p[1] + ".!!!not-base64!!!"
			},
			want: ErrMalformed,
		},
		{
			name: "authenticated but not flate data",
			token: func(t *testing.T) string {
				packed := []byte("this is not a flate stream at all")
				return keyNew.KID + "." + base64.RawURLEncoding.EncodeToString(packed) + "." +
					base64.RawURLEncoding.EncodeToString(tag(keyNew.Key, DomainState, packed))
			},
			want: ErrMalformed,
		},
		{
			name: "authenticated but not JSON",
			token: func(t *testing.T) string {
				packed, err := deflate([]byte("<html>not json</html>"))
				if err != nil {
					t.Fatalf("deflate: %v", err)
				}
				return keyNew.KID + "." + base64.RawURLEncoding.EncodeToString(packed) + "." +
					base64.RawURLEncoding.EncodeToString(tag(keyNew.Key, DomainState, packed))
			},
			want: ErrMalformed,
		},
		{
			name: "compression bomb over the cap",
			token: func(t *testing.T) string {
				var buf bytes.Buffer
				w, err := flate.NewWriter(&buf, flate.BestCompression)
				if err != nil {
					t.Fatalf("flate.NewWriter: %v", err)
				}
				// 8 MiB of zeros compresses to a handful of KiB.
				if _, err := w.Write(bytes.Repeat([]byte{0}, 8<<20)); err != nil {
					t.Fatalf("write: %v", err)
				}
				if err := w.Close(); err != nil {
					t.Fatalf("close: %v", err)
				}
				packed := buf.Bytes()
				if len(packed) > 64<<10 {
					t.Fatalf("bomb payload %d bytes, expected a small compressed form", len(packed))
				}
				return keyNew.KID + "." + base64.RawURLEncoding.EncodeToString(packed) + "." +
					base64.RawURLEncoding.EncodeToString(tag(keyNew.Key, DomainState, packed))
			},
			want: ErrMalformed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got StatePayload
			err := ring.Open(DomainState, tc.token(t), &got, testTTL, now)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Open error = %v, want errors.Is(_, %v)", err, tc.want)
			}
		})
	}
}

func TestIATWindow(t *testing.T) {
	now := fixedNow()
	ring := testRing()

	tests := []struct {
		name string
		iat  time.Time
		ttl  time.Duration
		want error // nil means accepted
	}{
		{name: "fresh", iat: now, ttl: testTTL},
		{name: "just inside ttl", iat: now.Add(-testTTL + time.Second), ttl: testTTL},
		{name: "exactly at ttl", iat: now.Add(-testTTL), ttl: testTTL},
		{name: "one second past ttl", iat: now.Add(-testTTL - time.Second), ttl: testTTL, want: ErrExpired},
		{name: "long expired", iat: now.Add(-24 * time.Hour), ttl: testTTL, want: ErrExpired},
		{name: "future within skew", iat: now.Add(30 * time.Second), ttl: testTTL},
		{name: "future at skew boundary", iat: now.Add(maxClockSkew), ttl: testTTL},
		{name: "future beyond skew", iat: now.Add(maxClockSkew + time.Second), ttl: testTTL, want: ErrFuture},
		{name: "far future", iat: now.Add(72 * time.Hour), ttl: testTTL, want: ErrFuture},
		{name: "zero ttl disables staleness", iat: now.Add(-72 * time.Hour), ttl: 0},
		{name: "zero ttl still rejects the future", iat: now.Add(time.Hour), ttl: 0, want: ErrFuture},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token, err := ring.Seal(DomainCode, CodePayload{CID: "90001", SC: "C", IAT: tc.iat.Unix()})
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			var got CodePayload
			err = ring.Open(DomainCode, token, &got, tc.ttl, now)
			switch {
			case tc.want == nil && err != nil:
				t.Fatalf("Open error = %v, want nil", err)
			case tc.want != nil && !errors.Is(err, tc.want):
				t.Fatalf("Open error = %v, want errors.Is(_, %v)", err, tc.want)
			}
			// Future-dating is also reported as an expiry so that callers
			// checking ErrExpired handle the whole window in one branch.
			if tc.want == ErrFuture && !errors.Is(err, ErrExpired) {
				t.Errorf("future-dated error %v does not satisfy errors.Is(_, ErrExpired)", err)
			}
		})
	}
}

// TestCrossDomainConfusion is the domain-separation guarantee: a token minted
// under one domain must never authenticate under another, and the rejection
// must be a MAC failure (i.e. before any payload parsing).
func TestCrossDomainConfusion(t *testing.T) {
	now := fixedNow()
	ring := testRing()

	stateTok, err := ring.Seal(DomainState, StatePayload{CID: "90001", RU: "https://app.example/cb", IAT: now.Unix()})
	if err != nil {
		t.Fatalf("Seal state: %v", err)
	}
	codeTok, err := ring.Seal(DomainCode, CodePayload{CID: "90001", SC: "C", IAT: now.Unix()})
	if err != nil {
		t.Fatalf("Seal code: %v", err)
	}

	tests := []struct {
		name   string
		domain string
		token  string
		dst    any
	}{
		{name: "state opened as code", domain: DomainCode, token: stateTok, dst: new(CodePayload)},
		{name: "code opened as state", domain: DomainState, token: codeTok, dst: new(StatePayload)},
		{name: "state opened under empty domain", domain: "", token: stateTok, dst: new(StatePayload)},
		{name: "state opened under future domain", domain: "sapstate.v2", token: stateTok, dst: new(StatePayload)},
		{name: "code opened under prefix of its domain", domain: "sapcode.v", token: codeTok, dst: new(CodePayload)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ring.Open(tc.domain, tc.token, tc.dst, testTTL, now)
			if !errors.Is(err, ErrBadMAC) {
				t.Fatalf("Open error = %v, want errors.Is(_, ErrBadMAC)", err)
			}
		})
	}

	// Sanity: each token still opens under its own domain.
	if err := ring.Open(DomainState, stateTok, new(StatePayload), testTTL, now); err != nil {
		t.Errorf("state token under its own domain: %v", err)
	}
	if err := ring.Open(DomainCode, codeTok, new(CodePayload), testTTL, now); err != nil {
		t.Errorf("code token under its own domain: %v", err)
	}
}

func TestKeyRotation(t *testing.T) {
	now := fixedNow()
	payload := StatePayload{CID: "90001", RU: "https://app.example/cb", IAT: now.Unix()}

	oldOnly := Ring{keyOld}
	rotated := Ring{keyNew, keyOld} // new key prepended, old still listed
	retired := Ring{keyNew}         // old key dropped after the TTL drained

	tokenOld, err := oldOnly.Seal(DomainState, payload)
	if err != nil {
		t.Fatalf("Seal with old key: %v", err)
	}
	tokenNew, err := rotated.Seal(DomainState, payload)
	if err != nil {
		t.Fatalf("Seal with rotated ring: %v", err)
	}

	if kid := strings.SplitN(tokenNew, ".", 2)[0]; kid != keyNew.KID {
		t.Fatalf("rotated ring signed with %q, want newest key %q", kid, keyNew.KID)
	}

	tests := []struct {
		name  string
		ring  Ring
		token string
		want  error
	}{
		{name: "in-flight token survives rotation", ring: rotated, token: tokenOld},
		{name: "new token under rotated ring", ring: rotated, token: tokenNew},
		{name: "old token after retirement", ring: retired, token: tokenOld, want: ErrUnknownKID},
		{name: "new token under old-only ring", ring: oldOnly, token: tokenNew, want: ErrUnknownKID},
		{name: "old token under old-only ring", ring: oldOnly, token: tokenOld},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got StatePayload
			err := tc.ring.Open(DomainState, tc.token, &got, testTTL, now)
			switch {
			case tc.want == nil && err != nil:
				t.Fatalf("Open error = %v, want nil", err)
			case tc.want != nil && !errors.Is(err, tc.want):
				t.Fatalf("Open error = %v, want errors.Is(_, %v)", err, tc.want)
			case tc.want == nil && got != payload:
				t.Errorf("payload = %+v, want %+v", got, payload)
			}
		})
	}
}

// TestForeignKeySameKID: an attacker who guesses the kid but not the key gets a
// MAC failure, not an acceptance.
func TestForeignKeySameKID(t *testing.T) {
	now := fixedNow()
	forged := Ring{{KID: keyNew.KID, Key: bytes.Repeat([]byte{0xff}, 32)}}
	token, err := forged.Seal(DomainState, StatePayload{CID: "evil", RU: "https://evil.example/cb", IAT: now.Unix()})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := testRing().Open(DomainState, token, new(StatePayload), testTTL, now); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("Open error = %v, want errors.Is(_, ErrBadMAC)", err)
	}
}

func TestEmptyRing(t *testing.T) {
	var empty Ring

	if _, err := empty.Seal(DomainState, StatePayload{}); !errors.Is(err, ErrEmptyRing) {
		t.Errorf("Seal error = %v, want errors.Is(_, ErrEmptyRing)", err)
	}
	if err := empty.Open(DomainState, "k1.AAAA.BBBB", new(StatePayload), testTTL, fixedNow()); !errors.Is(err, ErrEmptyRing) {
		t.Errorf("Open error = %v, want errors.Is(_, ErrEmptyRing)", err)
	}
	if _, err := (Ring{}).Seal(DomainCode, CodePayload{}); !errors.Is(err, ErrEmptyRing) {
		t.Errorf("Seal on zero-length ring error = %v, want errors.Is(_, ErrEmptyRing)", err)
	}
}

func TestSealUnusableKey(t *testing.T) {
	tests := []struct {
		name string
		ring Ring
		want error
	}{
		{name: "empty kid", ring: Ring{{KID: "", Key: keyNew.Key}}, want: ErrMalformed},
		{name: "kid with dot", ring: Ring{{KID: "k.2", Key: keyNew.Key}}, want: ErrMalformed},
		{name: "no key material", ring: Ring{{KID: "k2"}}, want: ErrEmptyRing},
		{name: "unmarshalable payload", ring: testRing(), want: ErrMalformed},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var payload any = StatePayload{}
			if tc.name == "unmarshalable payload" {
				payload = make(chan int)
			}
			if _, err := tc.ring.Seal(DomainState, payload); !errors.Is(err, tc.want) {
				t.Fatalf("Seal error = %v, want errors.Is(_, %v)", err, tc.want)
			}
		})
	}
}

// TestKeyWithoutMaterialIsNotUsableForOpen guards against a misconfigured ring
// entry silently authenticating tokens under a zero-length HMAC key.
func TestKeyWithoutMaterialIsNotUsableForOpen(t *testing.T) {
	now := fixedNow()
	packed, err := deflate([]byte(`{"cid":"x","sc":"y","iat":0}`))
	if err != nil {
		t.Fatalf("deflate: %v", err)
	}
	token := "kx." + base64.RawURLEncoding.EncodeToString(packed) + "." +
		base64.RawURLEncoding.EncodeToString(tag(nil, DomainCode, packed))

	ring := Ring{{KID: "kx"}, keyNew}
	if err := ring.Open(DomainCode, token, new(CodePayload), testTTL, now); !errors.Is(err, ErrUnknownKID) {
		t.Fatalf("Open error = %v, want errors.Is(_, ErrUnknownKID)", err)
	}
}

// TestCompressionHelpsLargeCallerState documents the flate reserve relied on by
// the 1 KB caller-state cap in the design.
func TestCompressionHelpsLargeCallerState(t *testing.T) {
	now := fixedNow()
	ring := testRing()
	want := StatePayload{
		CID:   "90001",
		RU:    "https://app.example/cb",
		ST:    strings.Repeat("a", 1024),
		HasST: true,
		IAT:   now.Unix(),
	}
	token, err := ring.Seal(DomainState, want)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(token) >= 1024 {
		t.Errorf("sealed token is %d bytes, expected compression to keep it well under the raw state size", len(token))
	}
	var got StatePayload
	if err := ring.Open(DomainState, token, &got, testTTL, now); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got != want {
		t.Errorf("round-trip mismatch")
	}
}

func TestOpenBadDestination(t *testing.T) {
	now := fixedNow()
	ring := testRing()
	token, err := ring.Seal(DomainCode, CodePayload{CID: "90001", SC: "C", IAT: now.Unix()})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// A non-pointer destination must yield an error, never a panic.
	if err := ring.Open(DomainCode, token, CodePayload{}, testTTL, now); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Open error = %v, want errors.Is(_, ErrMalformed)", err)
	}
	if err := ring.Open(DomainCode, token, nil, testTTL, now); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Open error = %v, want errors.Is(_, ErrMalformed)", err)
	}
}

// TestUnknownKIDErrorIsBounded guards a log-amplification lever: the kid is
// attacker-controlled and unbounded (a caller can present a multi-megabyte
// "kid.x.y" as a state or code), and the OAuth handlers log the error Open
// returns. The message must therefore not carry the whole kid.
func TestUnknownKIDErrorIsBounded(t *testing.T) {
	t.Parallel()

	huge := strings.Repeat("A", 1<<20)
	err := testRing().Open(DomainState, huge+".x.y", new(StatePayload), testTTL, fixedNow())
	if !errors.Is(err, ErrUnknownKID) {
		t.Fatalf("Open() error = %v, want ErrUnknownKID", err)
	}
	if len(err.Error()) > 256 {
		t.Errorf("error message is %d bytes; want it bounded (kid must be truncated)", len(err.Error()))
	}
	if strings.Contains(err.Error(), huge) {
		t.Error("error message embeds the full attacker-supplied kid")
	}
}
