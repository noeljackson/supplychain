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
	hits, err := ScanLockfiles(dir, iocs, nil)
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
	hits, err := ScanLockfiles(dir, iocs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 {
		t.Fatalf("len(hits)=%d, want 2 (%+v)", len(hits), hits)
	}
}

func TestPnpmMatchingUsesExactNameAndVersion(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "pnpm-lock.yaml")
	contents := `lockfileVersion: '9.0'
packages:
  safe-action-plus@0.8.4:
    resolution: {integrity: sha512-a}
  safe-action@10.8.40:
    resolution: {integrity: sha512-b}
`
	if err := os.WriteFile(lock, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	iocs := []ioc.PackageIOC{{Name: "safe-action", Version: "0.8.4"}}
	hits, err := ScanLockfiles(dir, iocs, []string{"safe-action"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Name != "safe-action" || hits[0].Version != "10.8.40" ||
		hits[0].Reason != "name-blocked" {
		t.Fatalf("unexpected exact matches: %+v", hits)
	}
}

func TestScanYarnV1AndBerryLocks(t *testing.T) {
	cases := map[string]string{
		"v1": `"safe-action@^0.8.0", "safe-action@~0.8.4":
  version "0.8.4"
  resolved "https://registry.yarnpkg.com/safe-action/-/safe-action-0.8.4.tgz"
"safe-action-plus@^0.8.0":
  version "0.8.4"
`,
		"berry": `__metadata:
  version: 8
"@scope/safe-action@npm:^0.8.0":
  version: 0.8.4
  resolution: "@scope/safe-action@npm:0.8.4"
`,
	}
	for name, contents := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			iocName := "safe-action"
			if name == "berry" {
				iocName = "@scope/safe-action"
			}
			hits, err := ScanLockfiles(dir, []ioc.PackageIOC{{Name: iocName, Version: "0.8.4"}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(hits) != 1 || hits[0].Name != iocName || hits[0].Version != "0.8.4" {
				t.Fatalf("unexpected Yarn matches: %+v", hits)
			}
		})
	}
}

func TestScanBunLockUsesParsedEntries(t *testing.T) {
	dir := t.TempDir()
	contents := `{
  "lockfileVersion": 1,
  "packages": {
    "safe-action": ["safe-action@0.8.4", "", {}, "sha512-good"],
    "safe-action-plus": ["safe-action-plus@0.8.4", "", {}, "sha512-good"]
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "bun.lock"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	hits, err := ScanLockfiles(
		dir,
		[]ioc.PackageIOC{{Name: "safe-action", Version: "0.8.4"}},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Name != "safe-action" {
		t.Fatalf("unexpected Bun matches: %+v", hits)
	}
}

func TestSupportedLockfileGoldenFixtures(t *testing.T) {
	fixtures := map[string]string{
		"package-lock-v3.json": "package-lock.json",
		"pnpm-lock-v9.yaml":    "pnpm-lock.yaml",
		"yarn-v1.lock":         "yarn.lock",
		"yarn-berry.lock":      "yarn.lock",
		"bun-v1.lock":          "bun.lock",
	}
	for fixture, destination := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("testdata", "locks", fixture))
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, destination), body, 0o600); err != nil {
				t.Fatal(err)
			}
			hits, err := ScanLockfiles(
				dir,
				[]ioc.PackageIOC{{Name: "safe-action", Version: "0.8.4"}},
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(hits) != 1 || hits[0].Name != "safe-action" ||
				hits[0].Version != "0.8.4" {
				t.Fatalf("golden fixture result = %+v", hits)
			}
		})
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

func FuzzParsePackageLock(f *testing.F) {
	f.Add([]byte(`{"lockfileVersion":3,"packages":{"node_modules/demo":{"version":"1.0.0"}}}`))
	f.Add([]byte(`{"dependencies":{"demo":{"version":"1.0.0"}}}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 1024*1024 {
			t.Skip()
		}
		_, _ = parseNpmLock(
			body,
			"package-lock.json",
			map[string]map[string]struct{}{"demo": {"1.0.0": {}}},
			map[string]struct{}{"blocked": {}},
		)
	})
}
