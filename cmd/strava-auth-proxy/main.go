// Command strava-auth-proxy serves Strava's OAuth surface for callers holding
// virtual client credentials, substitutes the real Strava application
// credentials on the upstream leg, and reverse-proxies everything under
// /api/v3/* verbatim.
//
// The whole process is two listeners:
//
//   - the public listener, carrying the OAuth endpoints and the /api/v3/*
//     catch-all proxy;
//   - the admin listener, carrying /healthz, /readyz and the expvar /metrics
//     endpoint, which is never exposed to callers.
//
// Configuration is loaded once at startup and re-read on SIGHUP; an invalid
// reload is logged and discarded, leaving the previous configuration live.
// SIGINT and SIGTERM shut both listeners down gracefully.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/glandais/strava-auth-proxy/internal/config"
	"github.com/glandais/strava-auth-proxy/internal/httpmid"
	"github.com/glandais/strava-auth-proxy/internal/oauth"
	"github.com/glandais/strava-auth-proxy/internal/seal"
	"github.com/glandais/strava-auth-proxy/internal/upstream"
)

// EnvLogLevel names the environment variable selecting the slog level
// ("debug", "info", "warn", "error"). Anything unparsable falls back to info.
const EnvLogLevel = "LOG_LEVEL"

// Server tuning.
const (
	// readHeaderTimeout bounds how long a caller may take to send its request
	// headers, which is the only slowloris surface the proxy has.
	readHeaderTimeout = 10 * time.Second
	// idleTimeout closes idle keep-alive connections.
	idleTimeout = 120 * time.Second
	// shutdownTimeout bounds graceful shutdown before in-flight requests are
	// dropped.
	shutdownTimeout = 20 * time.Second
)

// errPlainHTTPRefused is returned when the public listener would serve plain
// HTTP without an explicit development opt-in.
var errPlainHTTPRefused = errors.New(
	"refusing to serve plain HTTP on the public listener: set " +
		config.EnvTLSCertFile + " and " + config.EnvTLSKeyFile +
		", or set " + config.EnvDevAllowHTTP + "=true for local development only")

func main() {
	// SIGINT/SIGTERM cancel the root context; SIGHUP is handled separately
	// inside serve, because it must not terminate the process.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx); err != nil {
		slog.Default().Error("fatal", "error", err)
		os.Exit(1)
	}
}

// run loads the configuration, wires both listeners and serves until ctx is
// cancelled. It returns nil on a clean shutdown.
func run(ctx context.Context) error {
	logger := newLogger(os.Stdout, os.Getenv(EnvLogLevel))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	holder := config.NewHolder(cfg)

	a, err := newApp(holder, logger)
	if err != nil {
		return err
	}
	defer a.close()

	return a.serve(ctx)
}

// newLogger returns the process-wide JSON logger. An unrecognised level string
// is not fatal: the proxy starts at info level rather than refusing to boot
// over a logging preference.
func newLogger(w io.Writer, level string) *slog.Logger {
	lvl := slog.LevelInfo
	if s := strings.TrimSpace(level); s != "" {
		if err := lvl.UnmarshalText([]byte(strings.ToUpper(s))); err != nil {
			lvl = slog.LevelInfo
		}
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lvl}))
}

// app owns the two listeners and the two servers for one process lifetime.
type app struct {
	holder *config.Holder
	logger *slog.Logger

	public   *http.Server
	publicLn net.Listener
	admin    *http.Server
	adminLn  net.Listener

	// tlsCert and tlsKey are empty when the public listener runs plain HTTP
	// under the development opt-in.
	tlsCert, tlsKey string

	closeOnce sync.Once
}

// newApp builds the handlers and binds both listeners. It returns an error
// before binding anything if the public listener would be insecure.
func newApp(holder *config.Holder, logger *slog.Logger) (*app, error) {
	if holder == nil {
		return nil, errors.New("main: nil config holder")
	}
	cfg := holder.Get()
	if cfg == nil {
		return nil, errors.New("main: no configuration published")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if err := checkListenerSecurity(cfg); err != nil {
		return nil, err
	}

	base, err := url.Parse(cfg.UpstreamBaseURL)
	if err != nil {
		return nil, fmt.Errorf("main: parsing upstream base URL: %w", err)
	}
	if !base.IsAbs() || base.Host == "" {
		return nil, fmt.Errorf("main: upstream base URL %q is not absolute", cfg.UpstreamBaseURL)
	}

	// One hardened transport backs both the server-to-server OAuth calls and
	// the /api/v3/* reverse proxy, so they share a connection pool to the one
	// upstream host the proxy ever talks to.
	client := upstream.NewClient()
	proxy := upstream.NewProxy(base, client.Transport, logger)

	// The ring is logged, not injected: leaving oauth.Handler.Ring nil makes
	// the handlers derive the ring from the live configuration on every
	// request, so a SIGHUP that prepends a new key id takes effect without a
	// restart (see DESIGN.md §4 key-rotation runbook).
	ring := ringFrom(cfg)
	if len(ring) == 0 {
		return nil, errors.New("main: state key ring is empty")
	}
	logger.Info("state key ring loaded", "kids", kids(ring), "signing_kid", ring[0].KID)

	handler := publicHandler(holder, client, proxy, logger)

	errLog := newErrorLog(logger)
	publicSrv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          errLog,
		// NO WriteTimeout, deliberately. http.Server's WriteTimeout is an
		// absolute deadline on the whole response, not an idle timeout, so any
		// value would cut off long /api/v3 activity-stream downloads and large
		// uploads mid-flight. Slow-client protection comes from
		// ReadHeaderTimeout above and from the upstream transport's own
		// response-header timeout.
	}
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		publicSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	adminSrv := &http.Server{
		Handler:           adminHandler(),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		WriteTimeout:      15 * time.Second, // admin responses are small and bounded
		ErrorLog:          errLog,
	}

	publicLn, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("main: listening on %s: %w", cfg.ListenAddr, err)
	}
	adminLn, err := net.Listen("tcp", cfg.AdminAddr)
	if err != nil {
		_ = publicLn.Close()
		return nil, fmt.Errorf("main: listening on admin address %s: %w", cfg.AdminAddr, err)
	}

	return &app{
		holder:   holder,
		logger:   logger,
		public:   publicSrv,
		publicLn: publicLn,
		admin:    adminSrv,
		adminLn:  adminLn,
		tlsCert:  cfg.TLSCertFile,
		tlsKey:   cfg.TLSKeyFile,
	}, nil
}

// checkListenerSecurity refuses a public listener that would serve plain HTTP.
//
// config.Load enforces the same rule, so this is the second of two gates: it
// also covers configurations built in process (tests, future embedding) that
// never went through Load.
func checkListenerSecurity(cfg *config.Config) error {
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		return nil
	}
	if cfg.DevAllowHTTP {
		return nil
	}
	return errPlainHTTPRefused
}

// ringFrom converts the configured key ring into a seal.Ring. config and seal
// are intentionally decoupled — neither imports the other — so the conversion
// lives here, at the wiring layer.
func ringFrom(cfg *config.Config) seal.Ring {
	if cfg == nil {
		return nil
	}
	r := make(seal.Ring, 0, len(cfg.StateKeys))
	for _, k := range cfg.StateKeys {
		r = append(r, seal.Key{KID: k.KID, Key: k.Key})
	}
	return r
}

// kids returns the ring's key ids, which are non-secret identifiers.
func kids(r seal.Ring) []string {
	out := make([]string, 0, len(r))
	for _, k := range r {
		out = append(out, k.KID)
	}
	return out
}

// publicHandler builds the caller-facing handler chain.
//
// Routing: oauth.Handler registers exact patterns, including
// "POST /api/v3/oauth/token", before the "/api/v3/" catch-all proxy. ServeMux's
// most-specific-pattern rule makes the exact token route win, so a token
// exchange is never forwarded upstream with the caller's virtual credentials
// still attached.
func publicHandler(holder *config.Holder, client *http.Client, proxy http.Handler, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	h := &oauth.Handler{
		Cfg:    holder,
		Client: client,
		Logger: logger,
		// Ring is nil on purpose: see newApp.
	}
	h.Register(mux)
	mux.Handle("/api/v3/", proxy)

	// The hardening headers belong to the OAuth surface only. Adding no-store
	// to proxied /api/v3 responses would rewrite Strava's own cache semantics,
	// which the proxy relays verbatim.
	return httpmid.AccessLog(logger, oauthSurfaceHeaders(mux))
}

// oauthSurfaceHeaders applies httpmid.SecurityHeaders to the OAuth surface and
// leaves every other route untouched.
func oauthSurfaceHeaders(next http.Handler) http.Handler {
	hardened := httpmid.SecurityHeaders(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isOAuthSurface(r.URL.Path) {
			hardened.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isOAuthSurface reports whether path is one of the proxy's own OAuth
// endpoints. /api/v3/oauth/token is one of them despite its path: it is
// handled locally and its response must not be cached either.
func isOAuthSurface(path string) bool {
	return strings.HasPrefix(path, "/oauth/") || path == "/api/v3/oauth/token"
}

// adminHandler builds the admin listener's handler: liveness, readiness and
// expvar metrics. It is bound to ADMIN_ADDR (loopback by default) and must
// never be exposed to callers.
func adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writePlain(w, "ok\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		// Readiness deliberately does NOT probe Strava. The proxy is ready as
		// soon as it has a valid configuration and is accepting connections; a
		// Strava outage must surface to callers as clean 502/504 Faults, not
		// evict every replica from the load balancer at once.
		writePlain(w, "ready\n")
	})
	mux.Handle("GET /metrics", expvar.Handler())
	return mux
}

func writePlain(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, body)
}

// serve runs both listeners until ctx is cancelled or a listener fails, then
// shuts both down gracefully. SIGHUP triggers a validate-then-swap config
// reload without interrupting service.
func (a *app) serve(ctx context.Context) error {
	srvErr := make(chan error, 2)

	go func() {
		a.logger.Info("admin listener started", "addr", a.adminLn.Addr().String())
		srvErr <- ignoreClosed(a.admin.Serve(a.adminLn))
	}()
	go func() {
		scheme := "http"
		if a.tlsCert != "" {
			scheme = "https"
		}
		a.logger.Info("public listener started", "addr", a.publicLn.Addr().String(), "scheme", scheme)
		if a.tlsCert != "" && a.tlsKey != "" {
			srvErr <- ignoreClosed(a.public.ServeTLS(a.publicLn, a.tlsCert, a.tlsKey))
			return
		}
		srvErr <- ignoreClosed(a.public.Serve(a.publicLn))
	}()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	for {
		select {
		case <-ctx.Done():
			a.logger.Info("shutdown requested")
			return a.shutdown()
		case err := <-srvErr:
			if err != nil {
				// One listener died; take the other down with it rather than
				// serving half the surface.
				_ = a.shutdown()
				return err
			}
		case <-hup:
			if err := a.holder.Reload(); err != nil {
				// The previously validated configuration stays live.
				a.logger.Error("config reload failed, keeping previous configuration", "error", err)
				continue
			}
			cfg := a.holder.Get()
			a.logger.Info("config reloaded",
				"clients", len(cfg.Clients),
				"kids", kids(ringFrom(cfg)),
				"state_ttl", cfg.StateTTL.String())
		}
	}
}

// shutdown gracefully stops both servers, bounded by shutdownTimeout.
func (a *app) shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, srv := range []*http.Server{a.public, a.admin} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = srv.Shutdown(ctx)
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// close releases the listeners. It is safe to call after shutdown, which has
// already closed them.
func (a *app) close() {
	a.closeOnce.Do(func() {
		_ = a.publicLn.Close()
		_ = a.adminLn.Close()
	})
}

// ignoreClosed maps the expected "server closed" sentinel to a nil error.
func ignoreClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// newErrorLog adapts http.Server's *log.Logger error sink onto slog so the
// process emits a single structured stream.
func newErrorLog(logger *slog.Logger) *log.Logger {
	return log.New(slogWriter{logger: logger}, "", 0)
}

// slogWriter forwards the standard library's plain-text server diagnostics to
// the structured logger.
type slogWriter struct{ logger *slog.Logger }

func (w slogWriter) Write(p []byte) (int, error) {
	w.logger.Warn("http server", "msg", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
