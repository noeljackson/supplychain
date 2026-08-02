package scan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noeljackson/supplychain/internal/check"
	"github.com/noeljackson/supplychain/internal/drift"
	"github.com/noeljackson/supplychain/internal/manifest"
	"github.com/noeljackson/supplychain/internal/osv"
	"github.com/noeljackson/supplychain/internal/vendorartifact"
)

func init() {
	if os.Getenv("GO_WANT_SCAN_OSV_HELPER") != "1" ||
		filepath.Base(os.Args[0]) != "osv-scanner" {
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("osv-scanner fixture 1.0.0")
		os.Exit(0)
	}
	fmt.Print(os.Getenv("TEST_SCAN_OSV_OUTPUT"))
	if strings.TrimSpace(os.Getenv("TEST_SCAN_OSV_OUTPUT")) == "" {
		fmt.Print(`{"results":[]}`)
	}
	os.Exit(0)
}

func TestNoPackageSourcesIsNotApplicable(t *testing.T) {
	findings := Findings{OSVAvailable: true, OSVStatus: OSVUnavailable}
	if err := applyOSVResult(&findings, nil, osv.ErrNoPackageSources); err != nil {
		t.Fatal(err)
	}
	if findings.OSVStatus != OSVNotApplicable {
		t.Fatalf("status = %q, want %q", findings.OSVStatus, OSVNotApplicable)
	}
}

func TestRequireOSVFailsClosedWhenUnavailable(t *testing.T) {
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	t.Cleanup(func() { _ = os.Setenv("PATH", oldPath) })

	findings, err := Run(Options{
		Target:          t.TempDir(),
		BinDir:          filepath.Join(t.TempDir(), "missing"),
		OpenIOC:         testIOCs(t),
		RequireOSV:      true,
		RequireComplete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := findings.Coverage["osv"]
	if result.Status != check.StatusIncomplete || !result.Required {
		t.Fatalf("OSV coverage = %+v, want required incomplete", result)
	}
	if findings.DurationMS <= 0 || findings.Coverage["manifest_ioc"].DurationMS <= 0 {
		t.Fatalf("scan timings were not recorded: %+v", findings.Coverage)
	}
	if !findings.HasRequiredCoverageGaps() {
		t.Fatal("missing OSV must fail strict coverage")
	}
}

func testIOCs(t *testing.T) func(string) (fs.File, error) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"packages.txt", "persistence-paths.txt", "payload-filenames.txt", "blocked-package-names.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("# test\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return func(name string) (fs.File, error) { return os.Open(filepath.Join(dir, name)) }
}

func TestFindingClassification(t *testing.T) {
	advisoryOnly := Findings{
		OSV:   []osv.PackageVuln{{Name: "pkg", Version: "1.0.0"}},
		Drift: []drift.Hit{{Name: "pkg", Reason: "missing-from-lockfile"}},
	}
	if advisoryOnly.HasSupplyChainHits() {
		t.Fatal("OSV/drift advisories should not count as supply-chain indicators")
	}
	if !advisoryOnly.HasAdvisoryHits() {
		t.Fatal("expected advisory hits")
	}
	if !advisoryOnly.HasHits() {
		t.Fatal("expected HasHits to preserve any non-info finding semantics")
	}

	iocHit := Findings{
		Manifest: []manifest.ManifestHit{{Name: "pkg", BadVersion: "1.0.0"}},
	}
	if !iocHit.HasSupplyChainHits() {
		t.Fatal("IOC manifest hits should count as supply-chain indicators")
	}
	if iocHit.HasAdvisoryHits() {
		t.Fatal("IOC-only finding should not count as advisory-only")
	}

	vendoredHit := Findings{
		Vendored: []vendorartifact.Issue{{Code: "vendored-digest-mismatch", Package: "pkg@1.0.0"}},
	}
	if !vendoredHit.HasSupplyChainHits() {
		t.Fatal("vendored artifact verification failures should count as supply-chain indicators")
	}
}

func TestStrictPolicyEndToEndFixtures(t *testing.T) {
	tests := map[string]struct {
		setup        func(*testing.T, string)
		osvOutput    string
		wantSupply   bool
		wantGapCheck string
	}{
		"clean": {
			osvOutput: `{"results":[]}`,
		},
		"malicious": {
			setup: func(t *testing.T, target string) {
				writeScanFixture(t, filepath.Join(target, "package.json"),
					`{"dependencies":{"evil":"1.0.0"}}`)
			},
			osvOutput:  `{"results":[]}`,
			wantSupply: true,
		},
		"malformed lockfile": {
			setup: func(t *testing.T, target string) {
				writeScanFixture(t, filepath.Join(target, "package-lock.json"), `{`)
			},
			osvOutput:    `{"results":[]}`,
			wantGapCheck: "lockfile_ioc",
		},
		"malformed external output": {
			osvOutput:    `{`,
			wantGapCheck: "osv",
		},
	}
	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			target := t.TempDir()
			if testCase.setup != nil {
				testCase.setup(t, target)
			}
			binDir := fakeOSVScanner(t)
			t.Setenv("TEST_SCAN_OSV_OUTPUT", testCase.osvOutput)
			findings, err := Run(Options{
				Target:          target,
				BinDir:          binDir,
				OpenIOC:         strictFixtureIOCs(t),
				RequireOSV:      true,
				RequireComplete: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if findings.HasSupplyChainHits() != testCase.wantSupply {
				t.Fatalf("supply-chain result = %v, findings=%+v", findings.HasSupplyChainHits(), findings)
			}
			if testCase.wantGapCheck == "" {
				if findings.HasRequiredCoverageGaps() {
					t.Fatalf("unexpected strict coverage gap: %+v", findings.Coverage)
				}
			} else {
				result := findings.Coverage[testCase.wantGapCheck]
				if !result.Required ||
					(result.Status != check.StatusFailed && result.Status != check.StatusIncomplete) {
					t.Fatalf("%s result = %+v", testCase.wantGapCheck, result)
				}
			}
		})
	}
}

func fakeOSVScanner(t *testing.T) string {
	t.Helper()
	binDir := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(executable, filepath.Join(binDir, "osv-scanner")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GO_WANT_SCAN_OSV_HELPER", "1")
	return binDir
}

func strictFixtureIOCs(t *testing.T) func(string) (fs.File, error) {
	t.Helper()
	dir := t.TempDir()
	contents := map[string]string{
		"packages.txt":              "evil@1.0.0\nharmless@9.9.9\n",
		"persistence-paths.txt":     "# fixture\n",
		"payload-filenames.txt":     "# fixture\n",
		"blocked-package-names.txt": "# fixture\n",
	}
	for name, body := range contents {
		writeScanFixture(t, filepath.Join(dir, name), body)
	}
	return func(name string) (fs.File, error) { return os.Open(filepath.Join(dir, name)) }
}

func writeScanFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
