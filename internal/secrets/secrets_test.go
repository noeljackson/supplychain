package secrets

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func init() {
	if os.Getenv("GO_WANT_GITLEAKS_HELPER") != "1" {
		return
	}
	if filepath.Base(os.Args[0]) != "gitleaks" {
		os.Exit(13)
	}
	contents := "args:"
	for _, arg := range os.Args[1:] {
		contents += " <" + arg + ">"
	}
	contents += "\n"
	if cwd, err := os.Getwd(); err == nil {
		contents += "cwd:" + cwd + "\n"
	}
	if value := os.Getenv("GITLEAKS_ENABLE_ANALYTICS"); value != "" {
		contents += "GITLEAKS_ENABLE_ANALYTICS=" + value + "\n"
	}
	for _, name := range []string{"GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML"} {
		if value := os.Getenv(name); value != "" {
			contents += name + "=" + value + "\n"
		}
	}
	if err := os.WriteFile(os.Getenv("TEST_GITLEAKS_LOG"), []byte(contents), 0o600); err != nil {
		os.Exit(14)
	}
	if code, _ := strconv.Atoi(os.Getenv("TEST_GITLEAKS_EXIT")); code != 0 {
		os.Exit(code)
	}
	os.Exit(0)
}

func TestRunUsesPinnedFlags(t *testing.T) {
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "gitleaks.log")
	writeFakeGitleaks(t, binDir, logPath, 0)

	target := initGitTarget(t)
	t.Setenv("GITLEAKS_CONFIG", "/tmp/untrusted-gitleaks.toml")
	t.Setenv("GITLEAKS_CONFIG_TOML", "[allowlist]")
	if err := Run(target, binDir); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	got, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, want := range []string{
		"dir",
		"<.>",
		"--no-banner",
		"--no-color",
		"--redact",
		"--log-level",
		"warn",
		"--max-target-megabytes",
		"10",
		"--exit-code",
		"1",
		"GITLEAKS_ENABLE_ANALYTICS=false",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("fake gitleaks log missing %q:\n%s", want, text)
		}
	}
	for _, forbidden := range []string{"GITLEAKS_CONFIG=", "GITLEAKS_CONFIG_TOML="} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("fake gitleaks log contains untrusted config %q:\n%s", forbidden, text)
		}
	}
}

func TestRunPropagatesFindingExit(t *testing.T) {
	binDir := t.TempDir()
	writeFakeGitleaks(t, binDir, filepath.Join(t.TempDir(), "gitleaks.log"), 1)

	err := Run(initGitTarget(t), binDir)
	if err == nil || !strings.Contains(err.Error(), "gitleaks policy failed") {
		t.Fatalf("expected policy error, got %v", err)
	}
}

func TestStageGitVisibleExcludesIgnoredAndNonRegularFiles(t *testing.T) {
	target := initGitTarget(t)
	writeTestFile(t, filepath.Join(target, ".gitignore"), "target/\n")
	writeTestFile(t, filepath.Join(target, ".gitleaks.toml"), "[allowlist]\n")
	writeTestFile(t, filepath.Join(target, ".gitleaksignore"), "fake-fingerprint\n")
	writeTestFile(t, filepath.Join(target, "visible.txt"), "visible\n")
	writeTestFile(t, filepath.Join(target, "target", "generated.txt"), "ignored\n")
	if err := os.Symlink("tracked.txt", filepath.Join(target, "visible-link")); err != nil {
		t.Fatal(err)
	}

	scanRoot, cleanup, err := stageGitVisible(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	for _, path := range []string{"tracked.txt", ".gitignore", "visible.txt"} {
		if _, err := os.Stat(filepath.Join(scanRoot, path)); err != nil {
			t.Fatalf("expected %s in scan view: %v", path, err)
		}
	}
	for _, path := range []string{"target/generated.txt", "visible-link", ".gitleaks.toml", ".gitleaksignore"} {
		if _, err := os.Lstat(filepath.Join(scanRoot, path)); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be excluded, got %v", path, err)
		}
	}
}

func TestRunRequiresGitleaks(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	err := Run(t.TempDir(), "")
	if err == nil || !strings.Contains(err.Error(), "gitleaks is required") {
		t.Fatalf("expected missing gitleaks error, got %v", err)
	}
}

func writeFakeGitleaks(t *testing.T, binDir, logPath string, exitCode int) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(executable, filepath.Join(binDir, "gitleaks")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GO_WANT_GITLEAKS_HELPER", "1")
	t.Setenv("TEST_GITLEAKS_LOG", logPath)
	t.Setenv("TEST_GITLEAKS_EXIT", strconv.Itoa(exitCode))
}

func initGitTarget(t *testing.T) string {
	t.Helper()
	target := t.TempDir()
	writeTestFile(t, filepath.Join(target, "tracked.txt"), "tracked\n")
	for _, args := range [][]string{{"init", "--quiet"}, {"add", "tracked.txt"}} {
		cmd := exec.Command("git", append([]string{"-C", target}, args...)...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, output)
		}
	}
	return target
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}
