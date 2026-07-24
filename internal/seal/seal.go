// Package seal implements the HMAC envelope used to carry OAuth flow context
// through the browser without any server-side storage.
//
// An envelope is a compact, self-authenticating string:
//
//	kid "." base64url(flate(canonical JSON)) "." base64url(HMAC-SHA256)
//
// where the MAC is computed over the domain-separation prefix bytes followed by
// the compressed payload bytes. Domain separation is therefore cryptographic: a
// token minted for [DomainState] can never verify under [DomainCode], and the
// rejection happens before a single attacker-controlled byte is parsed.
//
// Envelopes are authenticated, not encrypted. Their contents are non-secret by
// construction (a virtual client id, a redirect URI, the caller's own state, and
// a Strava authorization code that is unusable without the real application
// secret), and readable envelopes keep flows debuggable.
package seal

import (
	"bytes"
	"compress/flate"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Domain-separation prefixes. They are mixed into the MAC input so that tokens
// of different kinds are cryptographically incompatible. No prefix is a prefix
// of another, so the unambiguity of the concatenation does not rely on a
// separator byte.
const (
	// DomainState is the prefix for the packed OAuth state token.
	DomainState = "sapstate.v1"
	// DomainCode is the prefix for the wrapped authorization code.
	DomainCode = "sapcode.v1"
)

const (
	// maxClockSkew is how far into the future an iat may sit before the
	// envelope is rejected; it absorbs benign clock drift between nodes.
	maxClockSkew = 60 * time.Second

	// maxPayloadBytes caps the size of the decompressed payload. It exists so
	// that a compression bomb cannot be inflated by a call to Open.
	maxPayloadBytes = 64 << 10 // 64 KiB

	// numParts is the number of "."-separated fields in an envelope.
	numParts = 3

	// maxLoggedKIDLen bounds how much of an envelope's key id may appear in an
	// error message. The kid is attacker-controlled and unbounded — a caller can
	// present a multi-megabyte "kid.x.y" as a state or code — and callers of Open
	// log the returned error, so an untruncated kid is a log-amplification lever.
	maxLoggedKIDLen = 64
)

// Sentinel errors returned (wrapped) by [Ring.Seal] and [Ring.Open]. Use
// errors.Is to test for them.
var (
	// ErrMalformed reports a structurally invalid envelope: wrong number of
	// parts, undecodable base64, an unusable kid, corrupt compressed data, or
	// a payload that is not valid JSON / exceeds the decompression cap.
	ErrMalformed = errors.New("seal: malformed envelope")

	// ErrUnknownKID reports that the envelope's key id is not present in the
	// ring — typically a retired key or a forgery.
	ErrUnknownKID = errors.New("seal: unknown key id")

	// ErrBadMAC reports that the envelope failed authentication: it was
	// tampered with, forged, or presented under the wrong domain prefix.
	ErrBadMAC = errors.New("seal: authentication failed")

	// ErrExpired reports that the envelope's iat falls outside the accepted
	// window: older than the TTL, or (together with ErrFuture) further in the
	// future than the allowed clock skew.
	ErrExpired = errors.New("seal: envelope expired")

	// ErrFuture reports an iat dated further into the future than the allowed
	// clock skew. Errors carrying it also satisfy errors.Is(err, ErrExpired).
	ErrFuture = errors.New("seal: envelope issued in the future")

	// ErrEmptyRing reports that the key ring holds no usable keys.
	ErrEmptyRing = errors.New("seal: empty key ring")
)

// b64 is the alphabet used for both envelope fields: URL-safe, unpadded.
var b64 = base64.RawURLEncoding

// Key is one entry of the HMAC key ring: a key id and the raw key bytes.
// KID travels in clear text inside every envelope and must not contain ".".
type Key struct {
	KID string
	Key []byte
}

// Ring is an ordered HMAC key ring, newest key first. [Ring.Seal] always signs
// with the newest key; [Ring.Open] accepts any key still listed, which is what
// makes rotation (prepend new, retire old after the TTL has drained) safe for
// in-flight authorizations.
type Ring []Key

// StatePayload is the payload of the packed state token sent to Strava as the
// state parameter. The caller sets IAT (unix seconds) before sealing.
//
// HasST distinguishes "the caller sent an empty state" from "the caller sent no
// state at all", which decides whether state is echoed on the final redirect.
type StatePayload struct {
	// CID is the virtual client id that started the flow.
	CID string `json:"cid"`
	// RU is the virtual client's original redirect_uri.
	RU string `json:"ru"`
	// ST is the caller's own state parameter, round-tripped bit-exact.
	ST string `json:"st"`
	// HasST records whether the caller supplied a state parameter at all.
	HasST bool `json:"has_st"`
	// IAT is the issue time, in unix seconds.
	IAT int64 `json:"iat"`
	// Nonce is the value of the optional __Host-sap_nonce double-submit
	// cookie; empty when the client does not opt into that hardening.
	Nonce string `json:"nonce"`
}

// CodePayload is the payload of the wrapped authorization code handed back to
// the virtual client. The caller sets IAT (unix seconds) before sealing.
type CodePayload struct {
	// CID is the virtual client the code was minted for; the token endpoint
	// requires the presenting client to match it.
	CID string `json:"cid"`
	// SC is Strava's raw authorization code.
	SC string `json:"sc"`
	// IAT is the issue time, in unix seconds.
	IAT int64 `json:"iat"`
}

// iatProbe extracts the issue time from an already authenticated payload
// without depending on the concrete destination type.
type iatProbe struct {
	IAT int64 `json:"iat"`
}

// Seal marshals payload to JSON, compresses it, and returns an envelope signed
// with the newest key in the ring under the given domain prefix.
//
// It returns ErrEmptyRing if the ring holds no key, and ErrMalformed if the
// newest key is unusable (empty or "."-bearing kid, empty key material) or the
// payload cannot be marshalled.
func (r Ring) Seal(domain string, payload any) (string, error) {
	if len(r) == 0 {
		return "", ErrEmptyRing
	}
	k := r[0]
	if k.KID == "" || strings.Contains(k.KID, ".") {
		return "", fmt.Errorf("seal: unusable key id %q: %w", k.KID, ErrMalformed)
	}
	if len(k.Key) == 0 {
		return "", fmt.Errorf("seal: key %q has no key material: %w", k.KID, ErrEmptyRing)
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("seal: marshal payload: %w: %w", ErrMalformed, err)
	}
	packed, err := deflate(raw)
	if err != nil {
		return "", fmt.Errorf("seal: compress payload: %w: %w", ErrMalformed, err)
	}

	var sb strings.Builder
	sb.WriteString(k.KID)
	sb.WriteByte('.')
	sb.WriteString(b64.EncodeToString(packed))
	sb.WriteByte('.')
	sb.WriteString(b64.EncodeToString(tag(k.Key, domain, packed)))
	return sb.String(), nil
}

// Open authenticates token under the given domain and, only once the MAC has
// passed, decodes its payload into dst and checks the issue-time window.
//
// The order of operations is security-critical and is exactly: split into three
// parts, look the kid up across the whole ring, verify the MAC with hmac.Equal,
// decompress (under a size cap) and unmarshal, then check that iat is neither
// older than ttl nor more than one minute ahead of now. No attacker-controlled
// bytes are interpreted before the MAC passes.
//
// dst must be a non-nil pointer to the payload type the token was sealed from.
// now is the reference time (pass time.Now() in production; a fixed instant in
// tests). A non-positive ttl disables the staleness check but not the
// future-dating check.
//
// Errors wrap ErrEmptyRing, ErrMalformed, ErrUnknownKID, ErrBadMAC, ErrExpired
// or ErrFuture.
func (r Ring) Open(domain, token string, dst any, ttl time.Duration, now time.Time) error {
	if len(r) == 0 {
		return ErrEmptyRing
	}

	// 1. Structure.
	parts := strings.Split(token, ".")
	if len(parts) != numParts {
		return fmt.Errorf("seal: got %d parts, want %d: %w", len(parts), numParts, ErrMalformed)
	}
	kid, payloadPart, macPart := parts[0], parts[1], parts[2]

	// 2. Key lookup. The kid is public metadata, not a secret.
	key, ok := r.key(kid)
	if !ok {
		return fmt.Errorf("seal: key id %q not in ring: %w", truncate(kid, maxLoggedKIDLen), ErrUnknownKID)
	}

	packed, err := b64.DecodeString(payloadPart)
	if err != nil {
		return fmt.Errorf("seal: decode payload: %w", ErrMalformed)
	}
	got, err := b64.DecodeString(macPart)
	if err != nil {
		return fmt.Errorf("seal: decode mac: %w", ErrMalformed)
	}

	// 3. Authentication. Nothing below this line runs on unauthenticated input.
	if !hmac.Equal(got, tag(key, domain, packed)) {
		return ErrBadMAC
	}

	// 4. Payload.
	raw, err := inflate(packed)
	if err != nil {
		return fmt.Errorf("seal: decompress payload: %w: %w", ErrMalformed, err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("seal: unmarshal payload: %w: %w", ErrMalformed, err)
	}

	// 5. Issue-time window.
	var probe iatProbe
	if err := json.Unmarshal(raw, &probe); err != nil {
		return fmt.Errorf("seal: unmarshal iat: %w: %w", ErrMalformed, err)
	}
	iat := time.Unix(probe.IAT, 0)
	if d := iat.Sub(now); d > maxClockSkew {
		return fmt.Errorf("seal: iat %s ahead of now: %w: %w", d, ErrExpired, ErrFuture)
	}
	if ttl > 0 {
		if age := now.Sub(iat); age > ttl {
			return fmt.Errorf("seal: age %s exceeds ttl %s: %w", age, ttl, ErrExpired)
		}
	}
	return nil
}

// truncate shortens s to at most n bytes, marking that it was cut. It is used
// only on values that reach error messages, never on values that are compared.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}

// key returns the ring entry with the given key id.
func (r Ring) key(kid string) ([]byte, bool) {
	for _, k := range r {
		if k.KID == kid && len(k.Key) > 0 {
			return k.Key, true
		}
	}
	return nil, false
}

// tag computes HMAC-SHA256(key, domain || packed).
func tag(key []byte, domain string, packed []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(domain))
	m.Write(packed)
	return m.Sum(nil)
}

// deflate compresses raw with the flate algorithm (no zlib/gzip framing).
func deflate(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(raw); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// inflate reverses deflate, refusing to expand beyond maxPayloadBytes so that a
// compression bomb costs a bounded amount of memory.
func inflate(packed []byte) ([]byte, error) {
	fr := flate.NewReader(bytes.NewReader(packed))
	defer fr.Close()

	raw, err := io.ReadAll(io.LimitReader(fr, maxPayloadBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxPayloadBytes {
		return nil, fmt.Errorf("payload exceeds %d bytes", maxPayloadBytes)
	}
	return raw, nil
}
