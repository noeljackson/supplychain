package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInitGitHubWritesHardenedWorkflow(t *testing.T) {
	t.Chdir(t.TempDir())
	const ref = "0123456789abcdef0123456789abcdef01234567"

	if got := cmdInit(&Globals{}, []string{"github", "--ref=" + ref}); got != 0 {
		t.Fatalf("cmdInit exit = %d, want 0", got)
	}
	contents, err := os.ReadFile(filepath.Join(".github", "workflows", "supplychain.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(contents)
	assertWorkflowSnapshot(t, "testdata/github-workflow.golden.yml", contents)
	for _, want := range []string{
		"pull_request:",
		"branches: [main]",
		"workflow_dispatch:",
		"contents: read",
		"cancel-in-progress: true",
		"/.github/workflows/scan.yml@" + ref,
		"policy: strict",
	} {
		if !strings.Contains(workflow, want) {
			t.Errorf("generated workflow missing %q", want)
		}
	}
	for _, forbidden := range []string{"pull_request_target", "secrets:", "permissions: write-all"} {
		if strings.Contains(workflow, forbidden) {
			t.Errorf("generated workflow contains unsafe setting %q", forbidden)
		}
	}
}

func TestInitGitHubRejectsMutableRef(t *testing.T) {
	t.Chdir(t.TempDir())
	if got := cmdInit(&Globals{}, []string{"github", "--ref=main"}); got != 2 {
		t.Fatalf("cmdInit exit = %d, want 2", got)
	}
	if _, err := os.Stat(filepath.Join(".github", "workflows", "supplychain.yml")); !os.IsNotExist(err) {
		t.Fatalf("workflow should not be created for mutable ref: %v", err)
	}
}

func TestInitGiteaWritesHardenedWorkflow(t *testing.T) {
	t.Chdir(t.TempDir())
	const ref = "0123456789abcdef0123456789abcdef01234567"

	if got := cmdInit(&Globals{}, []string{"gitea", "--ref=" + ref}); got != 0 {
		t.Fatalf("cmdInit exit = %d, want 0", got)
	}
	contents, err := os.ReadFile(filepath.Join(".gitea", "workflows", "supplychain.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(contents)
	assertWorkflowSnapshot(t, "testdata/gitea-workflow.golden.yml", contents)
	for _, want := range []string{
		"pull_request:",
		"branches: [main]",
		"workflow_dispatch:",
		"contents: read",
		"timeout-minutes: 20",
		"https://github.com/actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
		"https://github.com/noeljackson/supplychain@" + ref,
		"policy: strict",
	} {
		if !strings.Contains(workflow, want) {
			t.Errorf("generated workflow missing %q", want)
		}
	}
	for _, forbidden := range []string{"pull_request_target", "secrets:", "write-all", "@main"} {
		if strings.Contains(workflow, forbidden) {
			t.Errorf("generated workflow contains unsafe setting %q", forbidden)
		}
	}
}

func assertWorkflowSnapshot(t *testing.T, path string, actual []byte) {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	expected, err := os.ReadFile(filepath.Join(filepath.Dir(sourceFile), path))
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != string(expected) {
		t.Fatalf("governance-sensitive workflow snapshot changed:\n--- got ---\n%s\n--- want ---\n%s", actual, expected)
	}
}
