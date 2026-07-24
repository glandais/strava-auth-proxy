package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/glandais/strava-auth-proxy/internal/config"
)

// healthcheckFlag invokes the built-in health probe instead of starting the
// server.
//
// The container images are built FROM scratch and therefore have no shell,
// curl or wget for Docker's HEALTHCHECK to call. Probing through the binary
// itself is the standard answer, and it keeps the admin listener bound to
// loopback: the probe runs inside the container's network namespace, so the
// admin port never has to be published to reach it.
const healthcheckFlag = "-healthcheck"

// healthcheckTimeout bounds the probe. A liveness check that hangs is a
// failed liveness check.
const healthcheckTimeout = 3 * time.Second

// healthcheck requests /healthz on the admin listener and reports whether it
// answered 200. It deliberately does not load the full configuration: the
// probe must work even when the registry file or the Strava credentials are
// unreadable, so it only consults the one variable it needs.
func healthcheck(ctx context.Context, out io.Writer) error {
	addr := strings.TrimSpace(os.Getenv(config.EnvAdminAddr))
	if addr == "" {
		addr = config.DefaultAdminAddr
	}
	// A listener bound to a wildcard address is not dialable as such on every
	// stack; probe loopback instead, which is where it also listens.
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s=%q is not a host:port address: %w", config.EnvAdminAddr, addr, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		addr = net.JoinHostPort("127.0.0.1", port)
	}

	ctx, cancel := context.WithTimeout(ctx, healthcheckTimeout)
	defer cancel()

	url := "http://" + addr + "/healthz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %d, want 200", url, resp.StatusCode)
	}
	fmt.Fprintln(out, "ok")
	return nil
}
