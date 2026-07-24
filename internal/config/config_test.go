package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// keyHex returns a hex-encoded key of n bytes, all equal to b.
func keyHex(b byte, n int) string { return hex.EncodeToString(bytes.Repeat([]byte{b}, n)) }

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

const clientsJSON = `[
  {
    "client_id": "90001",
    "client_secret_sha256": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    "redirect_uris": ["https://gpxapp.example/strava/cb", "http://localhost:3000/cb"]
  },
  {
    "client_id": "90002",
    "client_secret": "plain-ok-for-dev",
    "redirect_uris": ["https://dash.example/oauth/return"],
    "require_nonce_cookie": true
  }
]`

// allEnvNames is every variable Load consults, including *_FILE siblings; the
// test harness clears them all so the ambient environment cannot leak in.
var allEnvNames = []string{
	EnvStravaClientID, EnvStravaClientID + "_FILE",
	EnvStravaClientSecret, EnvStravaClientSecret + "_FILE",
	EnvPublicURL, EnvPublicURL + "_FILE",
	EnvUpstreamBaseURL, EnvListenAddr, EnvAdminAddr,
	EnvTLSCertFile, EnvTLSKeyFile, EnvDevAllowHTTP,
	EnvStateKeys, EnvStateKeys + "_FILE", EnvStateTTL,
	EnvClients, EnvClientsFile,
}

func baseEnv() map[string]string {
	return map[string]string{
		EnvStravaClientID:     "12345",
		EnvStravaClientSecret: plaintextSecret,
		EnvPublicURL:          "https://proxy.example",
		EnvStateKeys:          "k2=" + keyHex(0xa1, 32) + ",k1=" + keyHex(0xb2, 48),
		EnvClients:            clientsJSON,
		EnvDevAllowHTTP:       "true",
	}
}

// applyEnv clears every known variable then applies env.
func applyEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for _, name := range allEnvNames {
		t.Setenv(name, "")
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestLoadDefaults(t *testing.T) {
	applyEnv(t, baseEnv())

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.StravaClientID != "12345" {
		t.Errorf("StravaClientID = %q", cfg.StravaClientID)
	}
	if cfg.StravaClientSecret.Reveal() != plaintextSecret {
		t.Error("StravaClientSecret did not round-trip")
	}
	if cfg.UpstreamBaseURL != DefaultUpstreamBaseURL {
		t.Errorf("UpstreamBaseURL = %q, want %q", cfg.UpstreamBaseURL, DefaultUpstreamBaseURL)
	}
	if cfg.ListenAddr != DefaultListenAddr {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, DefaultListenAddr)
	}
	if cfg.AdminAddr != DefaultAdminAddr {
		t.Errorf("AdminAddr = %q, want %q", cfg.AdminAddr, DefaultAdminAddr)
	}
	if cfg.StateTTL != DefaultStateTTL {
		t.Errorf("StateTTL = %s, want %s", cfg.StateTTL, DefaultStateTTL)
	}
	if got, want := cfg.CallbackURL(), "https://proxy.example/oauth/callback"; got != want {
		t.Errorf("CallbackURL() = %q, want %q", got, want)
	}
	if len(cfg.StateKeys) != 2 || cfg.StateKeys[0].KID != "k2" || cfg.StateKeys[1].KID != "k1" {
		t.Fatalf("StateKeys = %+v, want newest-first [k2 k1]", cfg.StateKeys)
	}
	if len(cfg.StateKeys[0].Key) != 32 || len(cfg.StateKeys[1].Key) != 48 {
		t.Errorf("key lengths = %d/%d, want 32/48", len(cfg.StateKeys[0].Key), len(cfg.StateKeys[1].Key))
	}
	if len(cfg.Clients) != 2 {
		t.Fatalf("len(Clients) = %d, want 2", len(cfg.Clients))
	}

	c1, ok := cfg.Client("90001")
	if !ok {
		t.Fatal("client 90001 missing")
	}
	if c1.RequireNonceCookie {
		t.Error("client 90001 should default RequireNonceCookie to false")
	}
	if !c1.VerifySecret("password") { // sha256("password") is the digest in clientsJSON
		t.Error("client 90001 should accept the pre-hashed secret")
	}
	c2, ok := cfg.Client("90002")
	if !ok {
		t.Fatal("client 90002 missing")
	}
	if !c2.RequireNonceCookie {
		t.Error("client 90002 should have RequireNonceCookie true")
	}
	if !c2.VerifySecret("plain-ok-for-dev") {
		t.Error("plaintext client secret was not hashed at load")
	}
	if _, ok := cfg.Client("99999"); ok {
		t.Error("unknown client id must not resolve")
	}
}

func TestLoadOverrides(t *testing.T) {
	env := baseEnv()
	env[EnvUpstreamBaseURL] = "http://127.0.0.1:9999/"
	env[EnvListenAddr] = ":9443"
	env[EnvAdminAddr] = "127.0.0.1:9191"
	env[EnvStateTTL] = "90s"
	env[EnvPublicURL] = "https://proxy.example///"
	env[EnvDevAllowHTTP] = "false"
	env[EnvTLSCertFile] = "/etc/proxy/tls.crt"
	env[EnvTLSKeyFile] = "/etc/proxy/tls.key"
	applyEnv(t, env)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.UpstreamBaseURL != "http://127.0.0.1:9999" {
		t.Errorf("UpstreamBaseURL = %q", cfg.UpstreamBaseURL)
	}
	if cfg.PublicURL != "https://proxy.example" {
		t.Errorf("PublicURL = %q, want trailing slashes trimmed", cfg.PublicURL)
	}
	if cfg.ListenAddr != ":9443" || cfg.AdminAddr != "127.0.0.1:9191" {
		t.Errorf("addrs = %q/%q", cfg.ListenAddr, cfg.AdminAddr)
	}
	if cfg.StateTTL != 90*time.Second {
		t.Errorf("StateTTL = %s, want 90s", cfg.StateTTL)
	}
	if cfg.DevAllowHTTP {
		t.Error("DevAllowHTTP should be false")
	}
}

func TestLoadValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(env map[string]string, t *testing.T)
		wantErr error
	}{
		{"ok baseline", func(map[string]string, *testing.T) {}, nil},
		{"missing strava client id", func(e map[string]string, _ *testing.T) {
			delete(e, EnvStravaClientID)
		}, ErrMissingStravaClientID},
		{"missing strava client secret", func(e map[string]string, _ *testing.T) {
			delete(e, EnvStravaClientSecret)
		}, ErrMissingStravaClientSecret},
		{"missing public url", func(e map[string]string, _ *testing.T) {
			delete(e, EnvPublicURL)
		}, ErrInvalidPublicURL},
		{"relative public url", func(e map[string]string, _ *testing.T) {
			e[EnvPublicURL] = "proxy.example"
		}, ErrInvalidPublicURL},
		{"public url with query", func(e map[string]string, _ *testing.T) {
			e[EnvPublicURL] = "https://proxy.example?x=1"
		}, ErrInvalidPublicURL},
		{"bad upstream base url", func(e map[string]string, _ *testing.T) {
			e[EnvUpstreamBaseURL] = "ftp://strava.example"
		}, ErrInvalidUpstreamBaseURL},
		{"bad bool", func(e map[string]string, _ *testing.T) {
			e[EnvDevAllowHTTP] = "yes-please"
		}, ErrInvalidBool},
		{"bad ttl", func(e map[string]string, _ *testing.T) {
			e[EnvStateTTL] = "fifteen minutes"
		}, ErrInvalidStateTTL},
		{"negative ttl", func(e map[string]string, _ *testing.T) {
			e[EnvStateTTL] = "-1m"
		}, ErrInvalidStateTTL},
		{"empty key ring", func(e map[string]string, _ *testing.T) {
			e[EnvStateKeys] = ""
		}, ErrEmptyKeyRing},
		{"key ring of commas only", func(e map[string]string, _ *testing.T) {
			e[EnvStateKeys] = " , , "
		}, ErrEmptyKeyRing},
		{"key without kid", func(e map[string]string, _ *testing.T) {
			e[EnvStateKeys] = keyHex(0x01, 32)
		}, ErrMalformedStateKey},
		{"key with empty value", func(e map[string]string, _ *testing.T) {
			e[EnvStateKeys] = "k1="
		}, ErrMalformedStateKey},
		{"kid containing the seal separator", func(e map[string]string, _ *testing.T) {
			e[EnvStateKeys] = "k.1=" + keyHex(0x01, 32)
		}, ErrMalformedStateKey},
		{"key not hex or base64", func(e map[string]string, _ *testing.T) {
			e[EnvStateKeys] = "k1=not*a*key*!!"
		}, ErrMalformedStateKey},
		{"short key", func(e map[string]string, _ *testing.T) {
			e[EnvStateKeys] = "k1=" + keyHex(0x01, 31)
		}, ErrShortStateKey},
		{"newest key ok, older key short", func(e map[string]string, _ *testing.T) {
			e[EnvStateKeys] = "k2=" + keyHex(0x01, 32) + ",k1=" + keyHex(0x02, 16)
		}, ErrShortStateKey},
		{"duplicate kid", func(e map[string]string, _ *testing.T) {
			e[EnvStateKeys] = "k1=" + keyHex(0x01, 32) + ",k1=" + keyHex(0x02, 32)
		}, ErrDuplicateKID},
		{"base64 key accepted", func(e map[string]string, _ *testing.T) {
			e[EnvStateKeys] = "k1=" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 43 raw-url chars = 32 bytes
		}, nil},
		{"no client registry", func(e map[string]string, _ *testing.T) {
			delete(e, EnvClients)
		}, ErrNoClientRegistry},
		{"malformed client json", func(e map[string]string, _ *testing.T) {
			e[EnvClients] = "{not json"
		}, ErrMalformedClients},
		{"empty client registry", func(e map[string]string, _ *testing.T) {
			e[EnvClients] = "[]"
		}, ErrNoClients},
		{"non numeric client id", func(e map[string]string, _ *testing.T) {
			e[EnvClients] = `[{"client_id":"app-1","client_secret":"s","redirect_uris":["https://a.example/cb"]}]`
		}, ErrInvalidClientID},
		{"empty client id", func(e map[string]string, _ *testing.T) {
			e[EnvClients] = `[{"client_id":"","client_secret":"s","redirect_uris":["https://a.example/cb"]}]`
		}, ErrInvalidClientID},
		{"duplicate client id", func(e map[string]string, _ *testing.T) {
			e[EnvClients] = `[{"client_id":"90001","client_secret":"s","redirect_uris":["https://a.example/cb"]},
			                  {"client_id":"90001","client_secret":"t","redirect_uris":["https://b.example/cb"]}]`
		}, ErrDuplicateClientID},
		{"client without redirect uris", func(e map[string]string, _ *testing.T) {
			e[EnvClients] = `[{"client_id":"90001","client_secret":"s","redirect_uris":[]}]`
		}, ErrNoRedirectURIs},
		{"client with missing redirect uris field", func(e map[string]string, _ *testing.T) {
			e[EnvClients] = `[{"client_id":"90001","client_secret":"s"}]`
		}, ErrNoRedirectURIs},
		{"http redirect uri on public host", func(e map[string]string, _ *testing.T) {
			e[EnvClients] = `[{"client_id":"90001","client_secret":"s","redirect_uris":["http://app.example/cb"]}]`
		}, ErrInsecureRedirectURI},
		{"non http scheme redirect uri", func(e map[string]string, _ *testing.T) {
			e[EnvClients] = `[{"client_id":"90001","client_secret":"s","redirect_uris":["myapp://cb"]}]`
		}, ErrInsecureRedirectURI},
		{"relative redirect uri", func(e map[string]string, _ *testing.T) {
			e[EnvClients] = `[{"client_id":"90001","client_secret":"s","redirect_uris":["/cb"]}]`
		}, ErrInvalidRedirectURI},
		{"redirect uri with fragment", func(e map[string]string, _ *testing.T) {
			e[EnvClients] = `[{"client_id":"90001","client_secret":"s","redirect_uris":["https://app.example/cb#frag"]}]`
		}, ErrInvalidRedirectURI},
		{"http localhost redirect uri allowed", func(e map[string]string, _ *testing.T) {
			e[EnvClients] = `[{"client_id":"90001","client_secret":"s","redirect_uris":["http://localhost:3000/cb"]}]`
		}, nil},
		{"http 127.0.0.1 redirect uri allowed", func(e map[string]string, _ *testing.T) {
			e[EnvClients] = `[{"client_id":"90001","client_secret":"s","redirect_uris":["http://127.0.0.1:3000/cb"]}]`
		}, nil},
		{"http [::1] redirect uri allowed", func(e map[string]string, _ *testing.T) {
			e[EnvClients] = `[{"client_id":"90001","client_secret":"s","redirect_uris":["http://[::1]:3000/cb"]}]`
		}, nil},
		{"both secret forms", func(e map[string]string, _ *testing.T) {
			e[EnvClients] = `[{"client_id":"90001","client_secret":"s","client_secret_sha256":"` +
				sha256Hex("s") + `","redirect_uris":["https://a.example/cb"]}]`
		}, ErrClientSecret},
		{"no secret at all", func(e map[string]string, _ *testing.T) {
			e[EnvClients] = `[{"client_id":"90001","redirect_uris":["https://a.example/cb"]}]`
		}, ErrClientSecret},
		{"secret digest not hex", func(e map[string]string, _ *testing.T) {
			e[EnvClients] = `[{"client_id":"90001","client_secret_sha256":"zzzz","redirect_uris":["https://a.example/cb"]}]`
		}, ErrClientSecret},
		{"secret digest wrong length", func(e map[string]string, _ *testing.T) {
			e[EnvClients] = `[{"client_id":"90001","client_secret_sha256":"aabb","redirect_uris":["https://a.example/cb"]}]`
		}, ErrClientSecret},
		{"tls required without dev flag", func(e map[string]string, _ *testing.T) {
			delete(e, EnvDevAllowHTTP)
		}, ErrTLSRequired},
		{"tls key without cert", func(e map[string]string, _ *testing.T) {
			delete(e, EnvDevAllowHTTP)
			e[EnvTLSKeyFile] = "/etc/proxy/tls.key"
		}, ErrTLSRequired},
		{"tls pair without dev flag ok", func(e map[string]string, _ *testing.T) {
			delete(e, EnvDevAllowHTTP)
			e[EnvTLSCertFile] = "/etc/proxy/tls.crt"
			e[EnvTLSKeyFile] = "/etc/proxy/tls.key"
		}, nil},
		{"missing clients file", func(e map[string]string, t *testing.T) {
			delete(e, EnvClients)
			e[EnvClientsFile] = filepath.Join(t.TempDir(), "does-not-exist.json")
		}, os.ErrNotExist},
		{"missing secret file", func(e map[string]string, t *testing.T) {
			e[EnvStravaClientSecret+"_FILE"] = filepath.Join(t.TempDir(), "nope")
		}, os.ErrNotExist},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := baseEnv()
			tt.mutate(env, t)
			applyEnv(t, env)

			cfg, err := Load()
			switch {
			case tt.wantErr == nil:
				if err != nil {
					t.Fatalf("Load() error = %v, want nil", err)
				}
				if cfg == nil {
					t.Fatal("Load() returned a nil config without an error")
				}
			default:
				if err == nil {
					t.Fatalf("Load() = %+v, want error %v", cfg, tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Load() error = %v, want errors.Is(_, %v)", err, tt.wantErr)
				}
				if cfg != nil {
					t.Errorf("Load() returned a non-nil config alongside error %v", err)
				}
			}
		})
	}
}

func TestLoadFileIndirection(t *testing.T) {
	secretPath := writeFile(t, "strava_secret", "file-secret\n")
	keysPath := writeFile(t, "state_keys", " k9="+keyHex(0x0f, 32)+"\n")
	urlPath := writeFile(t, "public_url", "https://from-file.example/\n")

	env := baseEnv()
	env[EnvStravaClientSecret] = "env-secret"
	env[EnvStravaClientSecret+"_FILE"] = secretPath
	env[EnvStateKeys] = "kenv=" + keyHex(0x01, 32)
	env[EnvStateKeys+"_FILE"] = keysPath
	env[EnvPublicURL+"_FILE"] = urlPath
	applyEnv(t, env)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.StravaClientSecret.Reveal(); got != "file-secret" {
		t.Errorf("secret = %q, want the *_FILE value with whitespace trimmed", got)
	}
	if len(cfg.StateKeys) != 1 || cfg.StateKeys[0].KID != "k9" {
		t.Errorf("StateKeys = %+v, want the *_FILE ring", cfg.StateKeys)
	}
	if cfg.PublicURL != "https://from-file.example" {
		t.Errorf("PublicURL = %q, want the *_FILE value", cfg.PublicURL)
	}
}

func TestLoadClientsFileWinsOverEnv(t *testing.T) {
	fileJSON := `[{"client_id":"70001","client_secret":"from-file","redirect_uris":["https://file.example/cb"]}]`
	path := writeFile(t, "clients.json", fileJSON)

	env := baseEnv()
	env[EnvClientsFile] = path
	applyEnv(t, env)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Clients) != 1 {
		t.Fatalf("len(Clients) = %d, want 1 (file must win over %s)", len(cfg.Clients), EnvClients)
	}
	if _, ok := cfg.Client("70001"); !ok {
		t.Error("client from PROXY_CLIENTS_FILE missing")
	}
	if _, ok := cfg.Client("90001"); ok {
		t.Error("client from PROXY_CLIENTS env fallback should have been ignored")
	}
}

func TestClientSecretForms(t *testing.T) {
	env := baseEnv()
	env[EnvClients] = `[
	  {"client_id":"90001","client_secret":"plain","redirect_uris":["https://a.example/cb"]},
	  {"client_id":"90002","client_secret_sha256":"` + sha256Hex("hashed") + `","redirect_uris":["https://b.example/cb"]}
	]`
	applyEnv(t, env)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	tests := []struct {
		id        string
		presented string
		want      bool
	}{
		{"90001", "plain", true},
		{"90001", "plain ", false},
		{"90001", "", false},
		{"90001", "hashed", false},
		{"90002", "hashed", true},
		{"90002", sha256Hex("hashed"), false},
		{"90002", "plain", false},
	}
	for _, tt := range tests {
		c, ok := cfg.Client(tt.id)
		if !ok {
			t.Fatalf("client %s missing", tt.id)
		}
		if got := c.VerifySecret(tt.presented); got != tt.want {
			t.Errorf("client %s VerifySecret(%q) = %v, want %v", tt.id, tt.presented, got, tt.want)
		}
	}
	var nilClient *Client
	if nilClient.VerifySecret("anything") {
		t.Error("nil client must not verify a secret")
	}
}

func TestAllowsRedirectURI(t *testing.T) {
	c := &Client{
		ID:           "90001",
		RedirectURIs: []string{"https://app.example/cb", "http://localhost:3000/cb"},
	}
	tests := []struct {
		uri  string
		want bool
	}{
		{"https://app.example/cb", true},
		{"http://localhost:3000/cb", true},
		{"https://app.example/cb/evil", false},
		{"https://app.example/cb/", false},
		{"https://app.example.evil/cb", false},
		{"https://app.example/cb?x=1", false},
		{"https://app.example/cb#f", false},
		{"https://APP.example/cb", false},
		{"http://app.example/cb", false},
		{"//app.example/cb", false},
		{" https://app.example/cb", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := c.AllowsRedirectURI(tt.uri); got != tt.want {
			t.Errorf("AllowsRedirectURI(%q) = %v, want %v", tt.uri, got, tt.want)
		}
	}
	var nilClient *Client
	if nilClient.AllowsRedirectURI("https://app.example/cb") {
		t.Error("nil client must not allow any redirect URI")
	}
}

func TestConfigClientNilSafety(t *testing.T) {
	var cfg *Config
	if _, ok := cfg.Client("90001"); ok {
		t.Error("nil config must not resolve a client")
	}
	empty := &Config{}
	if _, ok := empty.Client("90001"); ok {
		t.Error("config without a registry must not resolve a client")
	}
}

func TestHolderReload(t *testing.T) {
	applyEnv(t, baseEnv())
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	h := NewHolder(cfg)
	if h.Get() != cfg {
		t.Fatal("Get() did not return the published config")
	}

	// Successful reload swaps in the new snapshot.
	env := baseEnv()
	env[EnvClients] = `[{"client_id":"70007","client_secret":"s","redirect_uris":["https://new.example/cb"]}]`
	applyEnv(t, env)
	if err := h.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	reloaded := h.Get()
	if reloaded == cfg {
		t.Fatal("Reload did not swap in a new config")
	}
	if _, ok := reloaded.Client("70007"); !ok {
		t.Error("reloaded config missing the new client")
	}

	// Failing reload keeps the previous snapshot live.
	bad := baseEnv()
	bad[EnvClients] = `[{"client_id":"nope","client_secret":"s","redirect_uris":["https://new.example/cb"]}]`
	applyEnv(t, bad)
	err = h.Reload()
	if err == nil {
		t.Fatal("Reload() = nil, want an error for an invalid config")
	}
	if !errors.Is(err, ErrInvalidClientID) {
		t.Errorf("Reload error = %v, want errors.Is(_, ErrInvalidClientID)", err)
	}
	if h.Get() != reloaded {
		t.Error("failed Reload must keep the previous config live")
	}
	if _, ok := h.Get().Client("70007"); !ok {
		t.Error("previous config lost its client after a failed reload")
	}
}

func TestValidateRejectsHandBuiltConfig(t *testing.T) {
	valid := func() *Config {
		return &Config{
			StravaClientID:     "12345",
			StravaClientSecret: NewSecret("s"),
			PublicURL:          "https://proxy.example",
			UpstreamBaseURL:    DefaultUpstreamBaseURL,
			DevAllowHTTP:       true,
			StateKeys:          []StateKey{{KID: "k1", Key: bytes.Repeat([]byte{1}, 32)}},
			StateTTL:           DefaultStateTTL,
			Clients: map[string]*Client{
				"90001": {ID: "90001", RedirectURIs: []string{"https://a.example/cb"}},
			},
		}
	}
	if err := valid().validate(); err != nil {
		t.Fatalf("baseline validate: %v", err)
	}
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr error
	}{
		{"registry key mismatch", func(c *Config) {
			c.Clients = map[string]*Client{"90001": {ID: "90002", RedirectURIs: []string{"https://a.example/cb"}}}
		}, ErrInvalidClientID},
		{"short key", func(c *Config) {
			c.StateKeys = []StateKey{{KID: "k1", Key: bytes.Repeat([]byte{1}, 8)}}
		}, ErrShortStateKey},
		{"empty ring", func(c *Config) { c.StateKeys = nil }, ErrEmptyKeyRing},
		{"zero ttl", func(c *Config) { c.StateTTL = 0 }, ErrInvalidStateTTL},
		{"no clients", func(c *Config) { c.Clients = nil }, ErrNoClients},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := valid()
			tt.mutate(c)
			err := c.validate()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("validate() = %v, want errors.Is(_, %v)", err, tt.wantErr)
			}
		})
	}
}
