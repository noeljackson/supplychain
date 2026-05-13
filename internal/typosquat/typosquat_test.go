package typosquat

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"", "abc", 3},
		{"abc", "", 3},
		{"abc", "abc", 0},
		{"loadash", "lodash", 1},  // insertion
		{"expresss", "express", 1}, // insertion
		{"reactdom", "react-dom", 1}, // insertion
		{"chalk", "chalkk", 1},
		{"react", "preact", 1},
		{"react", "next", 3}, // r→n sub, a→x sub, delete c
	}
	for _, c := range cases {
		if got := levenshtein(c.a, c.b); got != c.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestClassify(t *testing.T) {
	// classify() uses DefaultMaxDistance = 1.
	cases := []struct {
		name      string
		wantHit   bool
		wantConf  string
		wantDist  int
	}{
		{"loadash", true, "lodash", 1},
		{"expresss", true, "express", 1},
		{"reactdom", true, "react-dom", 1},
		{"challk", true, "chalk", 1},
		// popular packages themselves shouldn't be flagged
		{"react", false, "", 0},
		{"lodash", false, "", 0},
		{"chalk", false, "", 0},
		// real-world distance-2 false positives — should NOT trigger at d=1
		{"vercel", false, "", 0},  // 2 edits from parcel
		{"jose", false, "", 0},    // 2 edits from joi (also too short to even consider)
		{"jiti", false, "", 0},    // 2 edits from vite (also too short)
		// too-far names
		{"completely-different-name", false, "", 0},
		{"some-niche-utility", false, "", 0},
		// too short
		{"foo", false, "", 0},
		{"abc", false, "", 0},
	}
	for _, c := range cases {
		h, ok := classify(c.name)
		if ok != c.wantHit {
			t.Errorf("classify(%q): hit=%v, want %v (got %+v)", c.name, ok, c.wantHit, h)
			continue
		}
		if !ok {
			continue
		}
		if h.Confused != c.wantConf {
			t.Errorf("classify(%q): confused=%q, want %q", c.name, h.Confused, c.wantConf)
		}
		if h.Distance != c.wantDist {
			t.Errorf("classify(%q): distance=%d, want %d", c.name, h.Distance, c.wantDist)
		}
	}
}

func TestCheck_FixturePackageJSON(t *testing.T) {
	dir := t.TempDir()
	pj := filepath.Join(dir, "package.json")
	contents := `{
  "name": "x",
  "dependencies": {
    "loadash": "^4",
    "react": "^18",
    "lodash": "^4"
  },
  "devDependencies": {
    "expresss": "^4"
  }
}`
	if err := writeFile(pj, contents); err != nil {
		t.Fatal(err)
	}
	hits, err := Check(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"loadash":  "lodash",
		"expresss": "express",
	}
	if len(hits) != len(want) {
		t.Fatalf("hits=%d, want %d (%+v)", len(hits), len(want), hits)
	}
	for _, h := range hits {
		if w, ok := want[h.Name]; !ok || w != h.Confused {
			t.Errorf("unexpected hit %+v", h)
		}
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
