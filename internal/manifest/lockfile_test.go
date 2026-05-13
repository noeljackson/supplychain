package manifest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/noeljackson/supplychain/internal/ioc"
)

func TestScanNpmLock_V3_WalksPackagesMap(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "package-lock.json")
	contents := `{
  "name": "x",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "x", "version": "1.0.0" },
    "node_modules/safe-action": { "version": "0.8.4" },
    "node_modules/@tanstack/router-utils": { "version": "1.161.11" },
    "node_modules/foo/node_modules/safe-action": { "version": "0.8.3" }
  }
}`
	if err := os.WriteFile(lock, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}

	iocs := []ioc.PackageIOC{
		{Name: "safe-action", Version: "0.8.3", Parsed: mustVer(t, "0.8.3")},
		{Name: "safe-action", Version: "0.8.4", Parsed: mustVer(t, "0.8.4")},
		{Name: "@tanstack/router-utils", Version: "1.161.11", Parsed: mustVer(t, "1.161.11")},
		{Name: "unrelated", Version: "9.9.9"},
	}
	hits, err := ScanLockfiles(dir, iocs)
	if err != nil {
		t.Fatal(err)
	}
	// We expect 3 hits: safe-action 0.8.4, @tanstack/router-utils 1.161.11,
	// and the nested safe-action 0.8.3.
	if len(hits) != 3 {
		t.Fatalf("len(hits)=%d, want 3 (%+v)", len(hits), hits)
	}
	have := map[string]bool{}
	for _, h := range hits {
		have[h.Name+"@"+h.Version] = true
	}
	for _, want := range []string{"safe-action@0.8.4", "safe-action@0.8.3", "@tanstack/router-utils@1.161.11"} {
		if !have[want] {
			t.Errorf("missing expected hit %q", want)
		}
	}
}

func TestScanLineLockfile_PnpmStyle(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "pnpm-lock.yaml")
	contents := `lockfileVersion: '9.0'
packages:
  '@tanstack/router-utils@1.161.11':
    resolution: {integrity: sha512-xxx}
  /safe-action@0.8.4:
    resolution: {integrity: sha512-yyy}
  '@some/unrelated@1.0.0':
    resolution: {integrity: sha512-zzz}
`
	if err := os.WriteFile(lock, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	iocs := []ioc.PackageIOC{
		{Name: "@tanstack/router-utils", Version: "1.161.11"},
		{Name: "safe-action", Version: "0.8.4"},
	}
	hits, err := ScanLockfiles(dir, iocs)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 {
		t.Fatalf("len(hits)=%d, want 2 (%+v)", len(hits), hits)
	}
}

func mustVer(t *testing.T, v string) *semver.Version {
	t.Helper()
	x, err := semver.NewVersion(v)
	if err != nil {
		t.Fatal(err)
	}
	return x
}
