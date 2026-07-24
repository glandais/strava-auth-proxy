// Package config loads, validates and hot-reloads the proxy configuration.
//
// Scalars and secrets come from the environment (with `*_FILE` indirection for
// orchestrator secret mounts); the virtual client registry is file-first
// (PROXY_CLIENTS_FILE) with a PROXY_CLIENTS JSON env fallback. Every rule is
// enforced fail-fast at load time, so an invalid configuration can never become
// live: [Holder.Reload] validates a fully built configuration before swapping it
// in, and keeps the previous one on any error.
package config

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Environment variable names read by [Load]. Every name listed here also honors
// a "<NAME>_FILE" sibling that takes precedence and names a file holding the
// value (trailing whitespace trimmed).
const (
	EnvStravaClientID     = "STRAVA_CLIENT_ID"
	EnvStravaClientSecret = "STRAVA_CLIENT_SECRET"
	EnvPublicURL          = "PROXY_PUBLIC_URL"
	EnvUpstreamBaseURL    = "UPSTREAM_BASE_URL"
	EnvListenAddr         = "LISTEN_ADDR"
	EnvAdminAddr          = "ADMIN_ADDR"
	EnvTLSCertFile        = "TLS_CERT_FILE"
	EnvTLSKeyFile         = "TLS_KEY_FILE"
	EnvDevAllowHTTP       = "DEV_ALLOW_HTTP"
	EnvStateKeys          = "PROXY_STATE_KEYS"
	EnvStateTTL           = "PROXY_STATE_TTL"
	EnvClients            = "PROXY_CLIENTS"
	EnvClientsFile        = "PROXY_CLIENTS_FILE"
)

// Defaults applied when the corresponding environment variable is unset.
const (
	DefaultUpstreamBaseURL = "https://www.strava.com"
	DefaultListenAddr      = ":8443"
	DefaultAdminAddr       = "127.0.0.1:9090"
	DefaultStateTTL        = 15 * time.Minute
)

// MinStateKeyLen is the minimum accepted length, in bytes, of an HMAC state key.
const MinStateKeyLen = 32

// Sentinel errors. Every error returned by [Load], [Holder.Reload] and the
// internal validators wraps one of these, so callers can branch with
// [errors.Is].
var (
	ErrMissingStravaClientID     = errors.New("config: " + EnvStravaClientID + " is required")
	ErrMissingStravaClientSecret = errors.New("config: " + EnvStravaClientSecret + " is required")
	ErrInvalidPublicURL          = errors.New("config: invalid " + EnvPublicURL)
	ErrInvalidUpstreamBaseURL    = errors.New("config: invalid " + EnvUpstreamBaseURL)
	ErrInvalidBool               = errors.New("config: invalid boolean value")
	ErrInvalidStateTTL           = errors.New("config: invalid " + EnvStateTTL)
	ErrEmptyKeyRing              = errors.New("config: state key ring is empty")
	ErrMalformedStateKey         = errors.New("config: malformed state key entry")
	ErrShortStateKey             = fmt.Errorf("config: state key must be at least %d bytes", MinStateKeyLen)
	ErrDuplicateKID              = errors.New("config: duplicate state key id")
	ErrNoClientRegistry          = errors.New("config: " + EnvClientsFile + " or " + EnvClients + " is required")
	ErrMalformedClients          = errors.New("config: malformed client registry")
	ErrNoClients                 = errors.New("config: client registry is empty")
	ErrInvalidClientID           = errors.New("config: client_id must be a non-empty all-digit string")
	ErrDuplicateClientID         = errors.New("config: duplicate client_id")
	ErrNoRedirectURIs            = errors.New("config: client must declare at least one redirect_uri")
	ErrInvalidRedirectURI        = errors.New("config: invalid redirect_uri")
	ErrInsecureRedirectURI       = errors.New("config: redirect_uri must use https (except localhost, 127.0.0.1, [::1])")
	ErrClientSecret              = errors.New("config: client secret is missing or malformed")
	ErrTLSRequired               = errors.New("config: " + EnvTLSCertFile + " and " + EnvTLSKeyFile + " are required unless " + EnvDevAllowHTTP + "=true")
)

// StateKey is one entry of the HMAC key ring: a key id and the raw key bytes.
type StateKey struct {
	KID string
	Key []byte
}

// Client is a registered virtual OAuth client. Its secret is stored only as a
// SHA-256 digest; the plaintext (when supplied for dev convenience) is hashed at
// load time and never retained.
type Client struct {
	ID                 string
	SecretSHA256       [32]byte
	RedirectURIs       []string
	RequireNonceCookie bool
}

// AllowsRedirectURI reports whether uri is allowlisted for this client. The
// comparison is an EXACT string match — no prefix, suffix or domain matching —
// because the proxy is the open-redirect chokepoint.
func (c *Client) AllowsRedirectURI(uri string) bool {
	if c == nil {
		return false
	}
	for _, allowed := range c.RedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

// VerifySecret reports whether presented is this client's secret. The presented
// value is hashed and compared to the stored digest with
// [subtle.ConstantTimeCompare] (equal-length inputs by construction), which
// prevents byte-position secret recovery.
func (c *Client) VerifySecret(presented string) bool {
	if c == nil {
		return false
	}
	sum := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(sum[:], c.SecretSHA256[:]) == 1
}

// Config is an immutable snapshot of the proxy configuration. Once published
// through a [Holder] it must never be mutated; reloads publish a new snapshot.
type Config struct {
	StravaClientID     string
	StravaClientSecret Secret
	PublicURL          string // e.g. "https://proxy.example" (no trailing slash)
	UpstreamBaseURL    string // default "https://www.strava.com" (test injection point)
	ListenAddr         string
	AdminAddr          string
	TLSCertFile        string
	TLSKeyFile         string
	DevAllowHTTP       bool
	StateKeys          []StateKey // newest first; sign with [0], verify against all
	StateTTL           time.Duration
	Clients            map[string]*Client
}

// Client returns the registered virtual client with the given id.
func (c *Config) Client(id string) (*Client, bool) {
	if c == nil || c.Clients == nil {
		return nil, false
	}
	cl, ok := c.Clients[id]
	return cl, ok
}

// CallbackURL is the redirect_uri registered on the real Strava application.
func (c *Config) CallbackURL() string { return c.PublicURL + "/oauth/callback" }

// Load builds a Config from the environment and fully validates it. It returns
// a non-nil error — and never a partially valid Config — if any rule fails.
func Load() (*Config, error) {
	c := &Config{
		StravaClientID:  strings.TrimSpace(os.Getenv(EnvStravaClientID)),
		UpstreamBaseURL: DefaultUpstreamBaseURL,
		ListenAddr:      DefaultListenAddr,
		AdminAddr:       DefaultAdminAddr,
		TLSCertFile:     strings.TrimSpace(os.Getenv(EnvTLSCertFile)),
		TLSKeyFile:      strings.TrimSpace(os.Getenv(EnvTLSKeyFile)),
		StateTTL:        DefaultStateTTL,
	}

	secret, err := envOrFile(EnvStravaClientSecret)
	if err != nil {
		return nil, err
	}
	c.StravaClientSecret = NewSecret(secret)

	publicURL, err := envOrFile(EnvPublicURL)
	if err != nil {
		return nil, err
	}
	c.PublicURL = strings.TrimRight(publicURL, "/")

	if v := strings.TrimSpace(os.Getenv(EnvUpstreamBaseURL)); v != "" {
		c.UpstreamBaseURL = strings.TrimRight(v, "/")
	}
	if v := strings.TrimSpace(os.Getenv(EnvListenAddr)); v != "" {
		c.ListenAddr = v
	}
	if v := strings.TrimSpace(os.Getenv(EnvAdminAddr)); v != "" {
		c.AdminAddr = v
	}
	if v := strings.TrimSpace(os.Getenv(EnvDevAllowHTTP)); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("%w: %s=%q", ErrInvalidBool, EnvDevAllowHTTP, v)
		}
		c.DevAllowHTTP = b
	}
	if v := strings.TrimSpace(os.Getenv(EnvStateTTL)); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrInvalidStateTTL, v, err)
		}
		c.StateTTL = d
	}

	keySpec, err := envOrFile(EnvStateKeys)
	if err != nil {
		return nil, err
	}
	if c.StateKeys, err = parseStateKeys(keySpec); err != nil {
		return nil, err
	}

	raw, err := loadClientRegistry()
	if err != nil {
		return nil, err
	}
	if c.Clients, err = parseClients(raw); err != nil {
		return nil, err
	}

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// envOrFile returns the value of name, preferring the "<name>_FILE" indirection
// when that variable is set to a non-empty path.
func envOrFile(name string) (string, error) {
	if path := strings.TrimSpace(os.Getenv(name + "_FILE")); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("config: reading %s_FILE: %w", name, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return strings.TrimSpace(os.Getenv(name)), nil
}

// loadClientRegistry returns the raw JSON registry: PROXY_CLIENTS_FILE is
// primary, PROXY_CLIENTS is the fallback.
func loadClientRegistry() ([]byte, error) {
	if path := strings.TrimSpace(os.Getenv(EnvClientsFile)); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config: reading %s: %w", EnvClientsFile, err)
		}
		return b, nil
	}
	if v := strings.TrimSpace(os.Getenv(EnvClients)); v != "" {
		return []byte(v), nil
	}
	return nil, ErrNoClientRegistry
}

// parseStateKeys parses a "kid=key,kid=key" ring, newest first. Keys are hex
// encoded (base64 is also accepted); every key must be at least
// [MinStateKeyLen] bytes and every kid must be unique and free of the "."
// separator used by the seal envelope format.
func parseStateKeys(spec string) ([]StateKey, error) {
	var keys []StateKey
	seen := make(map[string]bool)
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		kid, encoded, ok := strings.Cut(entry, "=")
		kid = strings.TrimSpace(kid)
		encoded = strings.TrimSpace(encoded)
		if !ok || kid == "" || encoded == "" {
			return nil, fmt.Errorf("%w: want \"kid=hexkey\", got %q", ErrMalformedStateKey, entry)
		}
		if !validKID(kid) {
			return nil, fmt.Errorf("%w: key id %q must match [A-Za-z0-9_-]+", ErrMalformedStateKey, kid)
		}
		if seen[kid] {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateKID, kid)
		}
		seen[kid] = true
		key, err := decodeKey(encoded)
		if err != nil {
			return nil, fmt.Errorf("%w: key %q: %v", ErrMalformedStateKey, kid, err)
		}
		if len(key) < MinStateKeyLen {
			return nil, fmt.Errorf("%w: key %q is %d bytes", ErrShortStateKey, kid, len(key))
		}
		keys = append(keys, StateKey{KID: kid, Key: key})
	}
	if len(keys) == 0 {
		return nil, ErrEmptyKeyRing
	}
	return keys, nil
}

func validKID(kid string) bool {
	for _, r := range kid {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return kid != ""
}

// decodeKey decodes a hex key, falling back to base64 (raw-url then standard).
func decodeKey(s string) ([]byte, error) {
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, errors.New("not valid hex or base64")
}

// clientJSON mirrors one entry of the client registry file.
type clientJSON struct {
	ClientID           string   `json:"client_id"`
	ClientSecretSHA256 string   `json:"client_secret_sha256"`
	ClientSecret       Secret   `json:"client_secret"`
	RedirectURIs       []string `json:"redirect_uris"`
	RequireNonceCookie bool     `json:"require_nonce_cookie"`
}

// parseClients decodes and validates the registry JSON.
func parseClients(raw []byte) (map[string]*Client, error) {
	var entries []clientJSON
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedClients, err)
	}
	clients := make(map[string]*Client, len(entries))
	for i, e := range entries {
		id := strings.TrimSpace(e.ClientID)
		if !isAllDigits(id) {
			return nil, fmt.Errorf("%w: entry %d: %q", ErrInvalidClientID, i, e.ClientID)
		}
		if _, dup := clients[id]; dup {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateClientID, id)
		}
		if len(e.RedirectURIs) == 0 {
			return nil, fmt.Errorf("%w: client %q", ErrNoRedirectURIs, id)
		}
		for _, uri := range e.RedirectURIs {
			if err := validateRedirectURI(uri); err != nil {
				return nil, fmt.Errorf("client %q: %w", id, err)
			}
		}
		digest, err := clientDigest(e)
		if err != nil {
			return nil, fmt.Errorf("client %q: %w", id, err)
		}
		clients[id] = &Client{
			ID:                 id,
			SecretSHA256:       digest,
			RedirectURIs:       append([]string(nil), e.RedirectURIs...),
			RequireNonceCookie: e.RequireNonceCookie,
		}
	}
	if len(clients) == 0 {
		return nil, ErrNoClients
	}
	return clients, nil
}

// clientDigest resolves the client's stored SHA-256 digest: the pre-hashed hex
// form is preferred, a plaintext secret is hashed at load (dev convenience).
func clientDigest(e clientJSON) ([32]byte, error) {
	var digest [32]byte
	hexDigest := strings.TrimSpace(e.ClientSecretSHA256)
	plaintext := e.ClientSecret.Reveal()
	switch {
	case hexDigest != "" && plaintext != "":
		return digest, fmt.Errorf("%w: set exactly one of client_secret_sha256 or client_secret", ErrClientSecret)
	case hexDigest != "":
		b, err := hex.DecodeString(hexDigest)
		if err != nil {
			return digest, fmt.Errorf("%w: client_secret_sha256 is not hex", ErrClientSecret)
		}
		if len(b) != sha256.Size {
			return digest, fmt.Errorf("%w: client_secret_sha256 must be %d hex-encoded bytes", ErrClientSecret, sha256.Size)
		}
		copy(digest[:], b)
	case plaintext != "":
		digest = sha256.Sum256([]byte(plaintext))
	default:
		return digest, fmt.Errorf("%w: neither client_secret_sha256 nor client_secret set", ErrClientSecret)
	}
	return digest, nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// loopbackHosts mirrors Strava's own localhost whitelist.
var loopbackHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}

// validateRedirectURI enforces absolute https URIs, with plain http tolerated
// only for loopback hosts.
func validateRedirectURI(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("%w: empty", ErrInvalidRedirectURI)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %q: %v", ErrInvalidRedirectURI, raw, err)
	}
	if u.Host == "" || !u.IsAbs() {
		return fmt.Errorf("%w: %q is not an absolute URI", ErrInvalidRedirectURI, raw)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("%w: %q must not contain a fragment", ErrInvalidRedirectURI, raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if loopbackHosts[u.Hostname()] {
			return nil
		}
		return fmt.Errorf("%w: %q", ErrInsecureRedirectURI, raw)
	default:
		return fmt.Errorf("%w: %q has unsupported scheme %q", ErrInsecureRedirectURI, raw, u.Scheme)
	}
}

// validate re-checks every invariant of an assembled Config. It is the single
// gate used by both [Load] and [Holder.Reload].
func (c *Config) validate() error {
	if c.StravaClientID == "" {
		return ErrMissingStravaClientID
	}
	if c.StravaClientSecret.IsZero() {
		return ErrMissingStravaClientSecret
	}
	if err := validateAbsURL(c.PublicURL, ErrInvalidPublicURL); err != nil {
		return err
	}
	if err := validateAbsURL(c.UpstreamBaseURL, ErrInvalidUpstreamBaseURL); err != nil {
		return err
	}
	if c.StateTTL <= 0 {
		return fmt.Errorf("%w: must be positive, got %s", ErrInvalidStateTTL, c.StateTTL)
	}
	if len(c.StateKeys) == 0 {
		return ErrEmptyKeyRing
	}
	seen := make(map[string]bool, len(c.StateKeys))
	for _, k := range c.StateKeys {
		if !validKID(k.KID) {
			return fmt.Errorf("%w: key id %q", ErrMalformedStateKey, k.KID)
		}
		if seen[k.KID] {
			return fmt.Errorf("%w: %q", ErrDuplicateKID, k.KID)
		}
		seen[k.KID] = true
		if len(k.Key) < MinStateKeyLen {
			return fmt.Errorf("%w: key %q is %d bytes", ErrShortStateKey, k.KID, len(k.Key))
		}
	}
	if len(c.Clients) == 0 {
		return ErrNoClients
	}
	for id, cl := range c.Clients {
		if !isAllDigits(id) {
			return fmt.Errorf("%w: %q", ErrInvalidClientID, id)
		}
		if cl == nil || cl.ID != id {
			return fmt.Errorf("%w: registry key %q does not match client id", ErrInvalidClientID, id)
		}
		if len(cl.RedirectURIs) == 0 {
			return fmt.Errorf("%w: client %q", ErrNoRedirectURIs, id)
		}
		for _, uri := range cl.RedirectURIs {
			if err := validateRedirectURI(uri); err != nil {
				return fmt.Errorf("client %q: %w", id, err)
			}
		}
	}
	if !c.DevAllowHTTP && (c.TLSCertFile == "" || c.TLSKeyFile == "") {
		return ErrTLSRequired
	}
	return nil
}

func validateAbsURL(raw string, sentinel error) error {
	if raw == "" {
		return fmt.Errorf("%w: empty", sentinel)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %q: %v", sentinel, raw, err)
	}
	if !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("%w: %q is not an absolute URL", sentinel, raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: %q has unsupported scheme %q", sentinel, raw, u.Scheme)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: %q must not carry a query or fragment", sentinel, raw)
	}
	return nil
}

// Holder publishes the live [Config] snapshot. Reads are lock-free and safe
// from any goroutine.
type Holder struct {
	p atomic.Pointer[Config]
}

// NewHolder returns a Holder publishing c.
func NewHolder(c *Config) *Holder {
	h := &Holder{}
	h.p.Store(c)
	return h
}

// Get returns the currently published configuration snapshot.
func (h *Holder) Get() *Config { return h.p.Load() }

// Reload re-reads and re-validates the configuration, swapping it in ONLY on
// success. On any error the previously published snapshot stays live.
func (h *Holder) Reload() error {
	c, err := Load()
	if err != nil {
		return err
	}
	h.p.Store(c)
	return nil
}
