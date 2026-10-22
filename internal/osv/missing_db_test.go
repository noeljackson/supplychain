package osv

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The test binary doubles as an osv-scanner that, like osv-scanner 2.4.0
// offline, finds a crates.io advisory, cannot load the Go database, and exits 1.
func init() {
	if os.Getenv("GO_WANT_OSV_MISSING_DB_HELPER") != "1" ||
		filepath.Base(os.Args[0]) != "osv-scanner" {
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("osv-scanner missing-db fixture 1.0.0")
		os.Exit(0)
	}
	if message := os.Getenv("TEST_OSV_MISSING_DB_STDERR"); message != "" {
		fmt.Fprintln(os.Stderr, message)
	}
	fmt.Print(`{"results":[{"source":{"path":"Cargo.lock"},"packages":[{"package":{"name":"time","version":"0.1.43","ecosystem":"crates.io"},"vulnerabilities":[{"id":"RUSTSEC-2020-0071"}]}]}]}`)
	os.Exit(1)
}

func missingDatabaseScanner(t *testing.T, stderr string) string {
	t.Helper()
	binDir := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(executable, filepath.Join(binDir, "osv-scanner")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GO_WANT_OSV_MISSING_DB_HELPER", "1")
	t.Setenv("TEST_OSV_MISSING_DB_STDERR", stderr)
	return binDir
}

const goDatabaseMissing = "could not load db for Go ecosystem: unable to fetch OSV database: no offline version of the OSV database is available"

func TestOfflineScanFailsWhenAnEcosystemDatabaseIsMissingBesideFindings(t *testing.T) {
	binDir := missingDatabaseScanner(t, goDatabaseMissing)
	_, err := Scan(binDir, t.TempDir(), true, nil)
	if !errors.Is(err, ErrOfflineDatabaseMissing) || !strings.Contains(err.Error(), "Go database") {
		t.Fatalf("Scan() error = %v, want the missing Go database", err)
	}
}

func TestOfflineScanNamesEveryMissingDatabaseOnce(t *testing.T) {
	binDir := missingDatabaseScanner(t, goDatabaseMissing+"\n"+
		"could not load db for npm ecosystem: unable to fetch OSV database\n"+goDatabaseMissing)
	_, err := Scan(binDir, t.TempDir(), true, nil)
	if err == nil || !strings.Contains(err.Error(), "the Go, npm database") {
		t.Fatalf("Scan() error = %v, want Go and npm named once each", err)
	}
}

func TestOfflineScanWithEveryDatabaseKeepsItsFindings(t *testing.T) {
	binDir := missingDatabaseScanner(t, "")
	findings, err := Scan(binDir, t.TempDir(), true, nil)
	if err != nil || len(findings) != 1 || findings[0].Name != "time" {
		t.Fatalf("Scan() = %+v, %v; want the crates.io finding", findings, err)
	}
}

func TestOnlineScanIgnoresOfflineDatabaseMessages(t *testing.T) {
	binDir := missingDatabaseScanner(t, goDatabaseMissing)
	findings, err := Scan(binDir, t.TempDir(), false, nil)
	if err != nil || len(findings) != 1 {
		t.Fatalf("Scan() = %+v, %v; want the online result unchanged", findings, err)
	}
}
