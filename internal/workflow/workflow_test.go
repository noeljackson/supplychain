package workflow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunSkipsTargetWithoutDefinitions(t *testing.T) {
	if err := Run(t.TempDir(), filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatalf("empty target should be a clean no-op: %v", err)
	}
}

func TestRunRequiresZizmorWhenDefinitionExists(t *testing.T) {
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "action.yml"), []byte("name: fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	err := Run(target, filepath.Join(t.TempDir(), "missing"))
	if err == nil || !strings.Contains(err.Error(), "zizmor is required") {
		t.Fatalf("expected fail-closed analyzer requirement, got %v", err)
	}
}

func TestContainsWorkflowDefinitions(t *testing.T) {
	target := t.TempDir()
	dir := filepath.Join(target, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ci.yaml"), []byte("name: ci\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	definitions, err := definitionPaths(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(definitions) != 1 || definitions[0] != filepath.Join(dir, "ci.yaml") {
		t.Fatal("expected workflow definition to be discovered")
	}
}

func TestContainsGiteaWorkflowDefinitions(t *testing.T) {
	target := t.TempDir()
	for _, directory := range []string{
		filepath.Join(target, ".gitea", "workflows"),
		filepath.Join(target, ".gitea", "scoped_workflows"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "supplychain.yml"), []byte("name: supplychain\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	definitions, err := definitionPaths(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(definitions) != 2 {
		t.Fatalf("expected two Gitea workflow definitions, got %v", definitions)
	}
}
