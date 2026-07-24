package seal

import (
	"encoding/base64"
	"testing"
	"time"
)

// FuzzOpen asserts the invariant that matters for a function fed
// attacker-controlled strings on every request path: Open never panics, and it
// never accepts a token it should not. Any envelope it does accept must have
// been produced by our own key.
func FuzzOpen(f *testing.F) {
	now := fixedNow()
	ring := testRing()

	stateTok, err := ring.Seal(DomainState, StatePayload{
		CID: "90001", RU: "https://app.example/cb", ST: "abc", HasST: true, IAT: now.Unix(),
	})
	if err != nil {
		f.Fatalf("Seal state: %v", err)
	}
	codeTok, err := ring.Seal(DomainCode, CodePayload{CID: "90001", SC: "C", IAT: now.Unix()})
	if err != nil {
		f.Fatalf("Seal code: %v", err)
	}

	packedJunk, err := deflate([]byte(`{"cid":1,"ru":[],"iat":"nope"}`))
	if err != nil {
		f.Fatalf("deflate: %v", err)
	}
	authedJunk := keyNew.KID + "." + base64.RawURLEncoding.EncodeToString(packedJunk) + "." +
		base64.RawURLEncoding.EncodeToString(tag(keyNew.Key, DomainState, packedJunk))

	seeds := []string{
		"",
		".",
		"..",
		"...",
		"k2..",
		"k2.AAAA.BBBB",
		"k99.AAAA.BBBB",
		"\x00.\x00.\x00",
		stateTok,
		codeTok,
		authedJunk,
		stateTok + ".",
		"k2." + stateTok,
	}
	for _, s := range seeds {
		f.Add(DomainState, s, int64(0))
		f.Add(DomainCode, s, int64(900))
	}

	f.Fuzz(func(t *testing.T, domain, token string, skewSec int64) {
		// Bound the offset so time.Unix arithmetic stays sane.
		ref := now.Add(time.Duration(skewSec%86_400) * time.Second)

		var st StatePayload
		if err := ring.Open(domain, token, &st, testTTL, ref); err == nil {
			if domain != DomainState && domain != DomainCode {
				t.Fatalf("accepted token %q under unexpected domain %q", token, domain)
			}
		}

		var cp CodePayload
		_ = ring.Open(domain, token, &cp, testTTL, ref)

		// Destinations Open must reject rather than panic on.
		_ = ring.Open(domain, token, nil, testTTL, ref)
		_ = ring.Open(domain, token, StatePayload{}, testTTL, ref)

		// Empty and single-key rings take different branches.
		_ = Ring(nil).Open(domain, token, &st, testTTL, ref)
		_ = Ring{keyOld}.Open(domain, token, &st, 0, ref)
	})
}
