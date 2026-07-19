package scan

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noeljackson/supplychain/internal/drift"
	"github.com/noeljackson/supplychain/internal/manifest"
	"github.com/noeljackson/supplychain/internal/osv"
)

func TestRequireOSVFailsClosedWhenUnavailable(t *testing.T) {
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	t.Cleanup(func() { _ = os.Setenv("PATH", oldPath) })

	_, err := Run(Options{
		Target:     t.TempDir(),
		BinDir:     filepath.Join(t.TempDir(), "missing"),
		OpenIOC:    testIOCs(t),
		RequireOSV: true,
	})
	if err == nil || !strings.Contains(err.Error(), "osv-scanner is required") {
		t.Fatalf("expected fail-closed OSV error, got %v", err)
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
}
