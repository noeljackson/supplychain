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
		"a":        "1.0.0",
		"@scope/b": "2.0.0",
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

func TestParseBunLock(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "bun.lock")
	// Trailing commas on purpose: bun.lock is JSONC, not strict JSON. The
	// path-prefixed "ws/typescript" key is a nested resolution that must NOT
	// override the hoisted "typescript" entry.
	write(t, lock, `{
	  "lockfileVersion": 1,
	  "packages": {
	    "turbo": ["turbo@2.9.16", "", {}, "sha512-aaa=="],
	    "@astrojs/compiler": ["@astrojs/compiler@2.13.1", "", {}, "sha512-bbb=="],
	    "picomatch": ["picomatch@4.0.3", "", {}, "sha512-ccc=="],
	    "typescript": ["typescript@6.0.3", "", {}, "sha512-ddd=="],
	    "@scope/app/typescript": ["typescript@5.9.3", "", {}, "sha512-eee=="],
	  },
	}`)
	got := parseBunLock(lock)
	want := map[string]string{
		"turbo":             "2.9.16",
		"@astrojs/compiler": "2.13.1",
		"picomatch":         "4.0.3",
		"typescript":        "6.0.3", // hoisted wins over nested 5.9.3
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

func TestSplitBunSpec(t *testing.T) {
	cases := []struct {
		in        string
		name, ver string
		ok        bool
	}{
		{"turbo@2.9.16", "turbo", "2.9.16", true},
		{"@scope/pkg@1.2.3", "@scope/pkg", "1.2.3", true},
		{"@scope/pkg", "", "", false}, // bare scoped name, no version
		{"noversion", "", "", false},
		{"trailing@", "", "", false},
	}
	for _, c := range cases {
		name, ver, ok := splitBunSpec(c.in)
		if ok != c.ok || name != c.name || ver != c.ver {
			t.Errorf("splitBunSpec(%q) = (%q,%q,%v), want (%q,%q,%v)", c.in, name, ver, ok, c.name, c.ver, c.ok)
		}
	}
}

// Regression: a bun.lock that actually contains the declared deps must NOT
// report them as "missing-from-lockfile". Before the parser existed, the nil
// version map made every declared dep look missing.
func TestScanRepo_BunLockNoFalseMissing(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "package.json"), `{
	  "devDependencies": {
	    "turbo":        "^2.9.0",
	    "typescript":   "^5.9.0",
	    "out-of-range": "^9.0.0"
	  }
	}`)
	write(t, filepath.Join(dir, "bun.lock"), `{
	  "lockfileVersion": 1,
	  "packages": {
	    "turbo":        ["turbo@2.9.16", "", {}, "sha512-a=="],
	    "typescript":   ["typescript@5.9.3", "", {}, "sha512-b=="],
	    "out-of-range": ["out-of-range@1.0.0", "", {}, "sha512-c=="],
	  },
	}`)

	hits, err := ScanRepo(dir)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Hit{}
	for _, h := range hits {
		byName[h.Name] = h
	}
	if h, ok := byName["turbo"]; ok {
		t.Errorf("turbo is present in bun.lock, should not be flagged: %+v", h)
	}
	if h, ok := byName["typescript"]; ok {
		t.Errorf("typescript is present in bun.lock, should not be flagged: %+v", h)
	}
	if h, ok := byName["out-of-range"]; !ok {
		t.Error("expected out-of-range hit")
	} else if h.Reason != "lockfile-out-of-range" || h.LockVersion != "1.0.0" {
		t.Errorf("out-of-range hit shape: %+v", h)
	}
}

func TestStripJSONTrailingCommas(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"a":1,}`, `{"a":1}`},
		{`[1,2,]`, `[1,2]`},
		{"{\n  \"a\": [1, 2,],\n}", "{\n  \"a\": [1, 2]\n}"}, // both trailing commas dropped
		{`{"s":"keep,this,comma","b":2,}`, `{"s":"keep,this,comma","b":2}`},
		{`{"s":"a]","b":[1],}`, `{"s":"a]","b":[1]}`},
		{`{"a":1}`, `{"a":1}`}, // no-op
	}
	for _, c := range cases {
		if got := string(stripJSONTrailingCommas([]byte(c.in))); got != c.want {
			t.Errorf("stripJSONTrailingCommas(%q) = %q, want %q", c.in, got, c.want)
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
