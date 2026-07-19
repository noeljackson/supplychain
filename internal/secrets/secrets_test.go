package secrets

import (
	"os"
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
	if value := os.Getenv("GITLEAKS_ENABLE_ANALYTICS"); value != "" {
		contents += "GITLEAKS_ENABLE_ANALYTICS=" + value + "\n"
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

	target := t.TempDir()
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
		target,
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
}

func TestRunPropagatesFindingExit(t *testing.T) {
	binDir := t.TempDir()
	writeFakeGitleaks(t, binDir, filepath.Join(t.TempDir(), "gitleaks.log"), 1)

	err := Run(t.TempDir(), binDir)
	if err == nil || !strings.Contains(err.Error(), "gitleaks policy failed") {
		t.Fatalf("expected policy error, got %v", err)
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
