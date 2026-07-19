package bunverify

import (
	"os"
	"path/filepath"
	"testing"
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

func TestSignatureVerification(t *testing.T) {
	// Registry key parsing and real signature verification are covered by the
	// integration command; this unit test keeps malformed input fail-closed.
	if verifySignature(nil, "not-base64", "pkg@1.0.0:sha512-x") {
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
