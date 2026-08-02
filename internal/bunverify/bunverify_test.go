package bunverify

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noeljackson/supplychain/internal/registry"
)

func TestParseLockfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bun.lock")
	contents := `{
  "lockfileVersion": 1,
  "packages": {
    "svelte": ["svelte@5.0.0", "", {}, "sha512-good"],
    "local": ["local@workspace:.", "", {}],
    "bad": ["bad@1.0.0", "github:someone/bad", {}, "sha512-bad"],
  },
}`
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	packages, issues, err := ParseLockfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 1 || packages[0].Name != "svelte" || packages[0].Version != "5.0.0" {
		t.Fatalf("unexpected packages: %+v", packages)
	}
	if len(issues) != 1 || issues[0].Code != "non-registry-source" {
		t.Fatalf("unexpected issues: %+v", issues)
	}
}

func TestParseLockfileRejectsUnsupportedVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bun.lock")
	if err := os.WriteFile(path, []byte(`{"lockfileVersion":2,"packages":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseLockfile(path); err == nil {
		t.Fatal("expected unsupported lockfile version error")
	}
}

func TestParseLockfileRejectsMalformedEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bun.lock")
	contents := `{"lockfileVersion":1,"packages":{"bad":{"descriptor":"bad@1.0.0"}}}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseLockfile(path); err == nil {
		t.Fatal("expected malformed package entry error")
	}
}

func TestParseLockfileValidatesEveryDuplicateSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bun.lock")
	contents := `{
  "lockfileVersion": 1,
  "packages": {
    "safe": ["same@1.0.0", "", {}, "sha512-good"],
    "unsafe": ["same@1.0.0", "github:someone/same", {}, "sha512-good"]
  }
}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	packages, issues, err := ParseLockfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 1 || packages[0].Name != "same" {
		t.Fatalf("packages = %+v", packages)
	}
	if len(issues) != 1 || issues[0].Code != "non-registry-source" {
		t.Fatalf("issues = %+v", issues)
	}
}

func TestSignatureVerification(t *testing.T) {
	// Registry key parsing and real signature verification are covered by the
	// integration command; this unit test keeps malformed input fail-closed.
	if registry.VerifySignature("not-a-key", "not-base64", "pkg@1.0.0:sha512-x") {
		t.Fatal("malformed signature unexpectedly verified")
	}
}

func TestSameStrings(t *testing.T) {
	if !sameStrings([]string{"a", "b"}, []string{"a", "b"}) {
		t.Fatal("equal slices differ")
	}
	if sameStrings([]string{"a"}, []string{"b"}) {
		t.Fatal("different slices compare equal")
	}
}

func TestResolveReviewedBaselineRejectsHostilePaths(t *testing.T) {
	target := t.TempDir()
	if err := exec.Command("git", "-C", target, "init", "-q").Run(); err != nil {
		t.Fatal(err)
	}
	policyDir := filepath.Join(target, ".supplychain")
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	baseline := filepath.Join(policyDir, "bun-baseline.json")
	if err := os.WriteFile(baseline, []byte(`{"version":1,"packages":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveReviewedBaseline(target, baseline); err == nil ||
		!strings.Contains(err.Error(), "tracked") {
		t.Fatalf("expected untracked rejection, got %v", err)
	}
	if err := exec.Command("git", "-C", target, "add", ".supplychain/bun-baseline.json").Run(); err != nil {
		t.Fatal(err)
	}
	if resolved, err := ResolveReviewedBaseline(target, baseline); err != nil || resolved != baseline {
		t.Fatalf("tracked baseline = %q, %v", resolved, err)
	}
	if _, err := ResolveReviewedBaseline(target, filepath.Join(t.TempDir(), "outside.json")); err == nil ||
		!strings.Contains(err.Error(), "inside") {
		t.Fatalf("expected outside rejection, got %v", err)
	}
	if err := os.Remove(baseline); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(policyDir, "real.json")
	if err := os.WriteFile(real, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.json", baseline); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveReviewedBaseline(target, baseline); err == nil ||
		!strings.Contains(err.Error(), "regular") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func FuzzParseBunLock(f *testing.F) {
	f.Add([]byte(`{"lockfileVersion":1,"packages":{"x":["x@1.0.0","",{},"sha512-x"]}}`))
	f.Add([]byte(`{"lockfileVersion":2,"packages":{}}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 1024*1024 {
			t.Skip()
		}
		_, _, _ = parseLockfile(body, "fuzz-bun.lock")
	})
}
