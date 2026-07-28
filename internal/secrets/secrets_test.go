package secrets

import (
	"context"
	"errors"
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
	if expected := os.Getenv("TEST_GITLEAKS_EXPECT_FILE"); expected != "" {
		body, err := os.ReadFile(expected)
		if err != nil {
			os.Exit(15)
		}
		if strings.Contains(string(body), "SECRET_FIXTURE_MARKER") {
			os.Exit(1)
		}
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
	if err := Run(target, binDir, ""); err != nil {
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
	if strings.Contains(text, "--max-target-megabytes") {
		t.Fatalf("strict scan must not silently skip large files:\n%s", text)
	}
}

func TestStageGitVisibleIncludesLargeGitVisibleFile(t *testing.T) {
	target := initGitTarget(t)
	path := filepath.Join(target, "large.bin")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(11 * 1024 * 1024); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	gitAdd(t, target, "large.bin")

	scanRoot, cleanup, err := stageGitVisible(context.Background(), target, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	info, err := os.Stat(filepath.Join(scanRoot, "large.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 11*1024*1024 {
		t.Fatalf("large staged file size = %d", info.Size())
	}
}

func TestRunDetectsRedactedFixtureBelowAndAboveTenMiB(t *testing.T) {
	for _, testCase := range []struct {
		name string
		size int64
	}{
		{name: "small", size: 1024},
		{name: "large", size: 11 * 1024 * 1024},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			binDir := t.TempDir()
			logPath := filepath.Join(t.TempDir(), "gitleaks.log")
			writeFakeGitleaks(t, binDir, logPath, 0)
			target := initGitTarget(t)
			path := filepath.Join(target, "credential.txt")
			file, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteString("SECRET_FIXTURE_MARKER\n"); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if err := file.Truncate(testCase.size); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			gitAdd(t, target, "credential.txt")
			// The staging directory is randomized. The helper receives its
			// working directory, so pass only the relative fixture name.
			t.Setenv("TEST_GITLEAKS_EXPECT_FILE", "credential.txt")
			err = Run(target, binDir, "")
			if !errors.Is(err, ErrFindings) {
				t.Fatalf("expected redacted finding for %d-byte fixture, got %v", testCase.size, err)
			}
			logBody, readErr := os.ReadFile(logPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if strings.Contains(string(logBody), "SECRET_FIXTURE_MARKER") {
				t.Fatal("secret fixture leaked into scanner log")
			}
		})
	}
}

func TestRunPropagatesFindingExit(t *testing.T) {
	binDir := t.TempDir()
	writeFakeGitleaks(t, binDir, filepath.Join(t.TempDir(), "gitleaks.log"), 1)

	err := Run(initGitTarget(t), binDir, "")
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

	scanRoot, cleanup, err := stageGitVisible(context.Background(), target, "")
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

	err := Run(t.TempDir(), "", "")
	if err == nil || !strings.Contains(err.Error(), "gitleaks is required") {
		t.Fatalf("expected missing gitleaks error, got %v", err)
	}
}

func TestRunUsesExplicitTrackedConfig(t *testing.T) {
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "gitleaks.log")
	writeFakeGitleaks(t, binDir, logPath, 0)

	target := initGitTarget(t)
	configPath := filepath.Join(target, "policy", "gitleaks.toml")
	writeTestFile(t, configPath, "[extend]\nuseDefault = true\n")
	gitAdd(t, target, "policy/gitleaks.toml")
	if err := Run(target, binDir, "policy/gitleaks.toml"); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	got, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, want := range []string{"<--config>", "<" + configPath + ">"} {
		if !strings.Contains(text, want) {
			t.Fatalf("fake gitleaks log missing %q:\n%s", want, text)
		}
	}
}

func TestResolveConfigAcceptsExplicitTrustedFile(t *testing.T) {
	target := t.TempDir()
	config := filepath.Join(t.TempDir(), "gitleaks.toml")
	if err := os.WriteFile(config, []byte("[allowlist]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	resolved, relative, err := resolveConfig(
		context.Background(), target, config, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != config || relative != "" {
		t.Fatalf("resolved = %q, relative = %q", resolved, relative)
	}
}

func TestRunRejectsUntrackedConfig(t *testing.T) {
	binDir := t.TempDir()
	writeFakeGitleaks(t, binDir, filepath.Join(t.TempDir(), "gitleaks.log"), 0)
	target := initGitTarget(t)
	writeTestFile(t, filepath.Join(target, ".gitleaks.toml"), "[extend]\nuseDefault = true\n")

	err := Run(target, binDir, ".gitleaks.toml")
	if err == nil || !strings.Contains(err.Error(), "must be tracked") {
		t.Fatalf("expected untracked config error, got %v", err)
	}
}

func TestRunRejectsConfigOutsideTarget(t *testing.T) {
	binDir := t.TempDir()
	writeFakeGitleaks(t, binDir, filepath.Join(t.TempDir(), "gitleaks.log"), 0)
	target := initGitTarget(t)
	outsideConfig := filepath.Join(t.TempDir(), "gitleaks.toml")
	writeTestFile(t, outsideConfig, "[extend]\nuseDefault = true\n")

	err := Run(target, binDir, outsideConfig)
	if err == nil || !strings.Contains(err.Error(), "inside the scan target") {
		t.Fatalf("expected outside-target config error, got %v", err)
	}
}

func TestRunRejectsConfigSymlink(t *testing.T) {
	binDir := t.TempDir()
	writeFakeGitleaks(t, binDir, filepath.Join(t.TempDir(), "gitleaks.log"), 0)
	target := initGitTarget(t)
	realConfig := filepath.Join(target, "policy.toml")
	writeTestFile(t, realConfig, "[extend]\nuseDefault = true\n")
	if err := os.Symlink("policy.toml", filepath.Join(target, ".gitleaks.toml")); err != nil {
		t.Fatal(err)
	}
	gitAdd(t, target, "policy.toml", ".gitleaks.toml")

	err := Run(target, binDir, ".gitleaks.toml")
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("expected symlink config error, got %v", err)
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

func gitAdd(t *testing.T, target string, paths ...string) {
	t.Helper()
	args := append([]string{"-C", target, "add", "--"}, paths...)
	if output, err := exec.Command("git", args...).CombinedOutput(); err != nil {
		t.Fatalf("git add %v: %v: %s", paths, err, output)
	}
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
