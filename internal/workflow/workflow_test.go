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

func TestContainsGiteaAndForgejoWorkflowDefinitions(t *testing.T) {
	target := t.TempDir()
	for _, directory := range []string{
		filepath.Join(target, ".gitea", "workflows"),
		filepath.Join(target, ".gitea", "scoped_workflows"),
		filepath.Join(target, ".forgejo", "workflows"),
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
	if len(definitions) != 3 {
		t.Fatalf("expected Gitea and Forgejo workflow definitions, got %v", definitions)
	}
}

func TestZizmorLoadsNoConfigurationFromTheAuditedTree(t *testing.T) {
	args := zizmorArgs([]string{"/repo/.gitea/workflows/ci.yaml"})
	if len(args) == 0 || args[0] != "--no-config" {
		t.Fatalf("zizmor may load a configuration from the audited tree: %q", args)
	}
	if args[len(args)-1] != "/repo/.gitea/workflows/ci.yaml" {
		t.Fatalf("definitions must remain the final arguments: %q", args)
	}
}
