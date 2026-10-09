package manifest

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestLockedPackagesListsRegistryEntriesAndSkipsWorkspaceSources(t *testing.T) {
	root := t.TempDir()
	lock := `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "0.0.0"},
    "node_modules/top": {"version": "1.0.0"},
    "node_modules/top/node_modules/deep": {"version": "2.0.0"},
    "node_modules/alias": {"name": "@scope/real", "version": "3.0.0"},
    "node_modules/workspace-pkg": {"link": true, "resolved": "packages/workspace-pkg"},
    "packages/workspace-pkg": {"version": "9.9.9"}
  }
}`
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	// A lockfile vendored inside an installed dependency is not the project's.
	vendored := filepath.Join(root, "node_modules", "top")
	if err := os.MkdirAll(vendored, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vendored, "package-lock.json"),
		[]byte(`{"packages":{"node_modules/vendored":{"version":"5.0.0"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LockedPackages(root)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, pkg := range got {
		names = append(names, pkg.Name+"@"+pkg.Version)
	}
	sort.Strings(names)
	want := []string{"@scope/real@3.0.0", "deep@2.0.0", "top@1.0.0"}
	if len(names) != len(want) {
		t.Fatalf("locked packages = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("locked packages = %v, want %v", names, want)
		}
	}
}

func TestLockedPackagesReadsV1Dependencies(t *testing.T) {
	root := t.TempDir()
	lock := `{"lockfileVersion": 1, "dependencies": {
  "top": {"version": "1.0.0", "dependencies": {"deep": {"version": "2.0.0"}}}
}}`
	if err := os.WriteFile(filepath.Join(root, "npm-shrinkwrap.json"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LockedPackages(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("locked packages = %+v, want top and deep", got)
	}
}
