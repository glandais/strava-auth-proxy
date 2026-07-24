// Package integration holds the end-to-end acceptance suite for the proxy
// (DESIGN.md §6).
//
// It contains no production code: every file except this one is a _test.go
// file. The suite stands up the real handler stack — the real
// [github.com/glandais/strava-auth-proxy/internal/oauth] handlers, the real
// [github.com/glandais/strava-auth-proxy/internal/upstream] transport and
// reverse proxy, the real [github.com/glandais/strava-auth-proxy/internal/httpmid]
// middleware chain, wired exactly as cmd/strava-auth-proxy does — in process,
// points it at [github.com/glandais/strava-auth-proxy/internal/fakestrava], and
// drives complete browser + backend flows through it.
//
// This package is the only one in the module permitted a third-party
// dependency, and only as a test dependency: golang.org/x/oauth2 backs the
// drop-in proof in dropin_test.go. The production binary must not depend on it,
// which `go list -deps ./cmd/...` asserts.
package integration
