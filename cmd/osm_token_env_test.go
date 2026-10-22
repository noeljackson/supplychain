package cmd

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// The test binary doubles as a fake osv-scanner. It records whether it
// inherited SUPPLYCHAIN_OSM_TOKEN and reports no findings.
func init() {
	report := os.Getenv("TEST_CMD_OSV_ENV_REPORT")
	if os.Getenv("GO_WANT_CMD_OSV_ENV_HELPER") != "1" || report == "" ||
		filepath.Base(os.Args[0]) != "osv-scanner" {
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("osv-scanner fixture 1.0.0")
		os.Exit(0)
	}
	_, present := os.LookupEnv("SUPPLYCHAIN_OSM_TOKEN")
	if err := os.WriteFile(report, []byte(strconv.FormatBool(present)), 0o600); err != nil {
		os.Exit(2)
	}
	fmt.Print(`{"results":[]}`)
	os.Exit(0)
}

// Run takes the token before any tool starts: the osv-scanner it runs during a
// scan never sees SUPPLYCHAIN_OSM_TOKEN, and the token is no longer in this
// process's environment afterwards.
func TestRunRemovesOSMTokenBeforeStartingTools(t *testing.T) {
	binDir := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(executable, filepath.Join(binDir, "osv-scanner")); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(t.TempDir(), "osv-env")
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "go.mod"), []byte("module example.com/fixture\n\ngo 1.22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GO_WANT_CMD_OSV_ENV_HELPER", "1")
	t.Setenv("TEST_CMD_OSV_ENV_REPORT", report)
	dataDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dataDir, "iocs"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"persistence-paths.txt", "payload-filenames.txt", "packages.txt",
		"c2-domains.txt", "dead-drop-signatures.txt", "blocked-package-names.txt",
	} {
		if err := os.WriteFile(filepath.Join(dataDir, "iocs", name), []byte("# fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SUPPLYCHAIN_BIN_DIR", binDir)
	t.Setenv("SUPPLYCHAIN_DATA_DIR", dataDir)
	t.Setenv("SUPPLYCHAIN_OSM_TOKEN", "synthetic-osm-token")

	// The scan's own report is not under test; keep it out of the test log.
	sink, err := os.Create(filepath.Join(t.TempDir(), "scan-output"))
	if err != nil {
		t.Fatal(err)
	}
	previousArgs, previousStdout, previousStderr := os.Args, os.Stdout, os.Stderr
	os.Args = []string{"supplychain", "--no-update", "--quiet", "scan", target}
	os.Stdout, os.Stderr = sink, sink
	t.Cleanup(func() {
		os.Args, os.Stdout, os.Stderr = previousArgs, previousStdout, previousStderr
		sink.Close()
	})
	Run(embed.FS{})
	os.Stdout, os.Stderr = previousStdout, previousStderr

	recorded, err := os.ReadFile(report)
	if err != nil {
		t.Fatalf("osv-scanner did not run during the scan: %v", err)
	}
	if string(recorded) != "false" {
		t.Fatalf("osv-scanner inherited SUPPLYCHAIN_OSM_TOKEN (report %q)", recorded)
	}
	if _, present := os.LookupEnv("SUPPLYCHAIN_OSM_TOKEN"); present {
		t.Fatal("SUPPLYCHAIN_OSM_TOKEN is still in the process environment after Run")
	}
}
