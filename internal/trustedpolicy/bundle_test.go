package trustedpolicy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveKnownFiles(t *testing.T) {
	directory := t.TempDir()
	sourcePolicy := filepath.Join(directory, SourcePolicyName)
	gitleaks := filepath.Join(directory, GitleaksName)
	for _, path := range []string{sourcePolicy, gitleaks} {
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	bundle, err := Resolve(directory)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.SourcePolicy != sourcePolicy || bundle.Gitleaks != gitleaks {
		t.Fatalf("unexpected bundle: %#v", bundle)
	}
	if bundle.BunBaseline != "" {
		t.Fatalf("missing baseline resolved as %q", bundle.BunBaseline)
	}
}

func TestResolveRejectsSymlinks(t *testing.T) {
	parent := t.TempDir()
	realDirectory := filepath.Join(parent, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	linkDirectory := filepath.Join(parent, "linked")
	if err := os.Symlink(realDirectory, linkDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(linkDirectory); err == nil {
		t.Fatal("expected symlinked directory to be rejected")
	}

	source := filepath.Join(parent, "source.json")
	if err := os.WriteFile(source, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(source, filepath.Join(realDirectory, SourcePolicyName)); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(realDirectory); err == nil {
		t.Fatal("expected symlinked policy file to be rejected")
	}
}
