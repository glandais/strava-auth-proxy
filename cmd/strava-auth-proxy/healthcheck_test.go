package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/glandais/strava-auth-proxy/internal/config"
)

// listenLoopback starts h on a loopback port and returns its host:port.
func listenLoopback(t *testing.T, h http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := httptest.NewUnstartedServer(h)
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return ln.Addr().String()
}

func TestHealthcheckSucceedsAgainstAdminListener(t *testing.T) {
	addr := listenLoopback(t, adminHandler())
	t.Setenv(config.EnvAdminAddr, addr)

	var out strings.Builder
	if err := healthcheck(context.Background(), &out); err != nil {
		t.Fatalf("healthcheck: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != "ok" {
		t.Errorf("output = %q, want %q", got, "ok")
	}
}

func TestHealthcheckFailsOnNonOKStatus(t *testing.T) {
	addr := listenLoopback(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Setenv(config.EnvAdminAddr, addr)

	err := healthcheck(context.Background(), io.Discard)
	if err == nil {
		t.Fatal("healthcheck succeeded against a 503 listener, want failure")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error = %v, want it to mention the status code", err)
	}
}

func TestHealthcheckFailsWhenNothingIsListening(t *testing.T) {
	// Bind then release a port so the address is well-formed but dead.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	t.Setenv(config.EnvAdminAddr, addr)

	if err := healthcheck(context.Background(), io.Discard); err == nil {
		t.Fatal("healthcheck succeeded with no listener, want failure")
	}
}

// A wildcard ADMIN_ADDR — what a container sets to expose the admin port — is
// not reliably dialable as written, so the probe must rewrite it to loopback.
func TestHealthcheckRewritesWildcardAddressToLoopback(t *testing.T) {
	addr := listenLoopback(t, adminHandler())
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	t.Setenv(config.EnvAdminAddr, "0.0.0.0:"+port)

	if err := healthcheck(context.Background(), io.Discard); err != nil {
		t.Fatalf("healthcheck with wildcard address: %v", err)
	}
}

func TestHealthcheckRejectsMalformedAdminAddr(t *testing.T) {
	t.Setenv(config.EnvAdminAddr, "not-a-host-port")

	err := healthcheck(context.Background(), io.Discard)
	if err == nil {
		t.Fatal("healthcheck accepted a malformed address, want failure")
	}
	if !strings.Contains(err.Error(), config.EnvAdminAddr) {
		t.Errorf("error = %v, want it to name %s", err, config.EnvAdminAddr)
	}
}
