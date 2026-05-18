package drift

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanRepo_DetectsOutOfRangeAndMissing(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "package.json"), `{
	  "dependencies": {
	    "in-range":      "^1.2.0",
	    "out-of-range":  "^2.0.0",
	    "missing":       "^3.0.0",
	    "workspace-dep": "workspace:*",
	    "wild":          "*"
	  }
	}`)
	write(t, filepath.Join(dir, "package-lock.json"), `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {},
	    "node_modules/in-range":      { "version": "1.5.0" },
	    "node_modules/out-of-range":  { "version": "1.9.0" },
	    "node_modules/in-range/node_modules/sub": { "version": "0.0.1" }
	  }
	}`)

	hits, err := ScanRepo(dir)
	if err != nil {
		t.Fatal(err)
	}

	byName := map[string]Hit{}
	for _, h := range hits {
		byName[h.Name] = h
	}
	if h, ok := byName["out-of-range"]; !ok {
		t.Error("expected out-of-range hit, got nothing")
	} else if h.Reason != "lockfile-out-of-range" || h.LockVersion != "1.9.0" {
		t.Errorf("out-of-range hit shape: %+v", h)
	}
	if h, ok := byName["missing"]; !ok {
		t.Error("expected missing-from-lockfile hit")
	} else if h.Reason != "missing-from-lockfile" {
		t.Errorf("missing hit reason: %s", h.Reason)
	}
	// Negative-space assertions
	if _, ok := byName["in-range"]; ok {
		t.Error("in-range dep should NOT be flagged")
	}
	if _, ok := byName["workspace-dep"]; ok {
		t.Error("workspace: spec should be skipped")
	}
	if _, ok := byName["wild"]; ok {
		t.Error("* spec should be skipped")
	}
}

func TestScanRepo_NoLockfileSkipsManifest(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "package.json"), `{"dependencies":{"x":"^1.0.0"}}`)
	hits, err := ScanRepo(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Errorf("expected no hits when no lockfile exists, got %v", hits)
	}
}

func TestParseNpmLock_TopLevelOnly(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "package-lock.json")
	write(t, lock, `{
	  "packages": {
	    "": {"name":"root"},
	    "node_modules/a": {"version":"1.0.0"},
	    "node_modules/@scope/b": {"version":"2.0.0"},
	    "node_modules/a/node_modules/c": {"version":"0.1.0"}
	  }
	}`)
	got := parseNpmLock(lock)
	want := map[string]string{
		"a":         "1.0.0",
		"@scope/b":  "2.0.0",
	}
	if len(got) != len(want) {
		t.Fatalf("len=%d, want %d (%+v)", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("[%s] got %q, want %q", k, got[k], v)
		}
	}
}

func TestIsSemverRange(t *testing.T) {
	yes := []string{"^1.2.3", "~1.2", "1.2.3", ">=1.0.0", "1.2.x", "1.x"}
	no := []string{
		"workspace:*", "workspace:^1.0.0",
		"file:../local", "link:../sibling",
		"github:user/repo", "git+https://example/r.git#v1",
		"http://example.com/x.tgz", "https://example.com/x.tgz",
		"npm:other-name@^1.0.0",
		"*", "x", "X", "latest",
	}
	for _, s := range yes {
		if !isSemverRange(s) {
			t.Errorf("isSemverRange(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if isSemverRange(s) {
			t.Errorf("isSemverRange(%q) = true, want false", s)
		}
	}
}
