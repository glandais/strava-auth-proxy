package integration

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// modulePath is this module's import path.
const modulePath = "github.com/glandais/strava-auth-proxy"

// TestProductionBinaryHasNoThirdPartyDependencies enforces the zero-dependency
// rule of DESIGN.md §3.
//
// golang.org/x/oauth2 is required by go.mod because dropin_test.go imports it,
// but it is a *test* dependency: nothing reachable from cmd/strava-auth-proxy
// may import it, or anything else outside the standard library.
func TestProductionBinaryHasNoThirdPartyDependencies(t *testing.T) {
	t.Parallel()

	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no go tool on PATH: %v", err)
	}

	// The test's working directory is the package directory, so the command
	// has to run from the module root for ./cmd/... to resolve.
	cmd := exec.Command(goBin, "list", "-deps", "./cmd/...")
	cmd.Dir = moduleRoot(t, goBin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps ./cmd/...: %v\n%s", err, out)
	}

	var offenders []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		pkg := strings.TrimSpace(line)
		if pkg == "" || strings.HasPrefix(pkg, modulePath) {
			continue
		}
		// Standard library import paths have no dot in their first element.
		first, _, _ := strings.Cut(pkg, "/")
		if strings.Contains(first, ".") {
			offenders = append(offenders, pkg)
		}
	}
	if len(offenders) > 0 {
		t.Errorf("the production binary depends on third-party packages: %v", offenders)
	}
	if strings.Contains(string(out), "golang.org/x/oauth2") {
		t.Error("golang.org/x/oauth2 must remain a test-only dependency")
	}
}

func moduleRoot(t *testing.T, goBin string) string {
	t.Helper()
	out, err := exec.Command(goBin, "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == "/dev/null" {
		t.Skip("not running inside a module")
	}
	return filepath.Dir(gomod)
}
