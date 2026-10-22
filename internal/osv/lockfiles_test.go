package osv

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The test binary doubles as an osv-scanner that records each invocation's
// arguments and exits with TEST_OSV_ARGS_EXIT.
func init() {
	record := os.Getenv("TEST_OSV_ARGS_RECORD")
	if os.Getenv("GO_WANT_OSV_ARGS_HELPER") != "1" || record == "" ||
		filepath.Base(os.Args[0]) != "osv-scanner" {
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		os.Stdout.WriteString("osv-scanner args fixture 1.0.0\n")
		os.Exit(0)
	}
	file, err := os.OpenFile(record, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(2)
	}
	file.WriteString(strings.Join(os.Args[1:], " ") + "\n")
	file.Close()
	code, _ := strconv.Atoi(os.Getenv("TEST_OSV_ARGS_EXIT"))
	if code == 0 || code == 1 {
		os.Stdout.WriteString(`{"results":[]}`)
	} else {
		os.Stderr.WriteString("extraction failed on specified lockfile\n")
	}
	os.Exit(code)
}

func argsRecordingScanner(t *testing.T, exit int) (string, string) {
	t.Helper()
	binDir := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(executable, filepath.Join(binDir, "osv-scanner")); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(t.TempDir(), "invocations")
	t.Setenv("GO_WANT_OSV_ARGS_HELPER", "1")
	t.Setenv("TEST_OSV_ARGS_RECORD", record)
	t.Setenv("TEST_OSV_ARGS_EXIT", strconv.Itoa(exit))
	return binDir, record
}

func invocations(t *testing.T, record string) []string {
	t.Helper()
	body, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(body)), "\n")
}

var derpLock = []Lockfile{{Format: "Cargo.lock", Path: "/repo/deployments/docker/derp.Cargo.lock"}}

func TestScanArgsNameEachLockfileBeforeTheTarget(t *testing.T) {
	args := strings.Join(scanArgs("/repo", true, derpLock), " ")
	want := "scan source --recursive --format json --lockfile Cargo.lock:/repo/deployments/docker/derp.Cargo.lock --offline --offline-vulnerabilities --no-resolve /repo"
	if args != want {
		t.Fatalf("scanArgs() = %q, want %q", args, want)
	}
}

func TestScanPassesNamedLockfiles(t *testing.T) {
	binDir, record := argsRecordingScanner(t, 0)
	if _, err := Scan(binDir, "/repo", false, derpLock); err != nil {
		t.Fatal(err)
	}
	calls := invocations(t, record)
	if len(calls) != 1 || !strings.Contains(calls[0], "--lockfile Cargo.lock:/repo/deployments/docker/derp.Cargo.lock") {
		t.Fatalf("osv-scanner invocations = %q", calls)
	}
}

// A malformed or missing named lockfile makes osv-scanner exit 127. Online
// scans used to retry with the legacy syntax, which cannot name lockfiles;
// with named lockfiles that retry would silently drop them.
func TestScanFailsInsteadOfDroppingNamedLockfiles(t *testing.T) {
	binDir, record := argsRecordingScanner(t, 127)
	_, err := Scan(binDir, "/repo", false, derpLock)
	if err == nil || !strings.Contains(err.Error(), "named lockfiles") {
		t.Fatalf("Scan() error = %v, want a named-lockfile failure", err)
	}
	if calls := invocations(t, record); len(calls) != 1 {
		t.Fatalf("osv-scanner ran %d times (%q); the legacy retry would drop the lockfile", len(calls), calls)
	}
}

func TestScanWithoutNamedLockfilesKeepsTheLegacyRetry(t *testing.T) {
	binDir, record := argsRecordingScanner(t, 127)
	_, err := Scan(binDir, "/repo", false, nil)
	if err == nil || errors.Is(err, ErrNoPackageSources) {
		t.Fatalf("Scan() error = %v, want the legacy failure", err)
	}
	if calls := invocations(t, record); len(calls) != 2 {
		t.Fatalf("osv-scanner ran %d times (%q), want the original and the legacy retry", len(calls), calls)
	}
}
