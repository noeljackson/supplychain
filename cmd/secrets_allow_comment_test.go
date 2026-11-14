package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The test binary doubles as a fake gitleaks that records its arguments and
// reports no findings.
func init() {
	record := os.Getenv("TEST_CMD_GITLEAKS_ARGS")
	if os.Getenv("GO_WANT_CMD_GITLEAKS_HELPER") != "1" || record == "" ||
		filepath.Base(os.Args[0]) != "gitleaks" {
		return
	}
	if err := os.WriteFile(record, []byte(strings.Join(os.Args[1:], "\n")+"\n"), 0o600); err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

// fakeGitleaks installs the recording gitleaks in a new bin directory and
// returns that directory and the file its arguments are written to.
func fakeGitleaks(t *testing.T) (binDir, record string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binDir = t.TempDir()
	if err := os.Symlink(executable, filepath.Join(binDir, "gitleaks")); err != nil {
		t.Fatal(err)
	}
	record = filepath.Join(t.TempDir(), "gitleaks-args")
	t.Setenv("GO_WANT_CMD_GITLEAKS_HELPER", "1")
	t.Setenv("TEST_CMD_GITLEAKS_ARGS", record)
	return binDir, record
}

func gitTarget(t *testing.T) string {
	t.Helper()
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "tracked.txt"), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "--quiet"}, {"add", "tracked.txt"}} {
		cmd := exec.Command("git", append([]string{"-C", target}, args...)...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, output)
		}
	}
	return target
}

// quiet keeps a command's own report out of the test log.
func quiet(t *testing.T, run func()) {
	t.Helper()
	sink, err := os.Create(filepath.Join(t.TempDir(), "command-output"))
	if err != nil {
		t.Fatal(err)
	}
	previousStdout, previousStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = sink, sink
	defer func() {
		os.Stdout, os.Stderr = previousStdout, previousStderr
		sink.Close()
	}()
	run()
}

func requireAllowCommentsIgnored(t *testing.T, record string) {
	t.Helper()
	recorded, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("gitleaks did not run: %v", err)
	}
	for _, arg := range strings.Split(string(recorded), "\n") {
		if arg == "--ignore-gitleaks-allow" {
			return
		}
	}
	t.Fatalf("gitleaks ran without --ignore-gitleaks-allow:\n%s", recorded)
}

// Every command that scans for secrets must tell Gitleaks to ignore inline
// allow comments: the scanned repository writes them, so a change under
// review could hide a secret beside one. One test per entry point, so that a
// path added later cannot drop the flag unnoticed.
func TestSecretsCommandIgnoresInlineAllowComments(t *testing.T) {
	binDir, record := fakeGitleaks(t)
	target := gitTarget(t)
	globals := &Globals{DataDir: t.TempDir(), BinDir: binDir}
	quiet(t, func() { cmdSecrets(globals, []string{target}) })
	requireAllowCommentsIgnored(t, record)
}

func TestCICommandIgnoresInlineAllowComments(t *testing.T) {
	binDir, record := fakeGitleaks(t)
	target := gitTarget(t)
	globals := &Globals{DataDir: t.TempDir(), BinDir: binDir}
	// The other scanners are absent here, so the command as a whole fails;
	// the secret scan still runs, and its arguments are what is under test.
	quiet(t, func() { cmdCI(globals, []string{target}) })
	requireAllowCommentsIgnored(t, record)
}
