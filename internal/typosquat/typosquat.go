// Package typosquat flags dependencies whose names are 1–2 edits away from a
// known popular npm package — the canonical pattern for typosquat-style
// supply-chain attacks (`loadash`, `expresss`, `colorss`, etc.).
package typosquat

import (
	_ "embed"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

//go:embed popular-npm-names.txt
var popularRaw string

// DefaultMaxDistance is the Levenshtein threshold used when the caller doesn't
// override it. We default to 1: that's the regime where typosquats are
// unambiguous (`loadash` vs `lodash`, `expresss` vs `express`). Distance 2
// pulls in too many legitimate packages that happen to be lexically close
// to a popular name (`vercel` vs `parcel`, `jose` vs `joi`, `jiti` vs `vite`),
// so callers must opt into it explicitly.
const DefaultMaxDistance = 1

// Hit is a single dependency name flagged as similar to a popular package.
type Hit struct {
	Name      string `json:"name"`       // the suspect dep name
	Confused  string `json:"confused"`   // the popular name it's close to
	Distance  int    `json:"distance"`   // Levenshtein distance
	Source    string `json:"source"`     // path to the package.json that declares it
	Section   string `json:"section"`    // dependencies | devDependencies | ...
}

// popular returns the parsed popular-names list, lazily initialised.
var popular = func() []string {
	var out []string
	for _, line := range strings.Split(popularRaw, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}()

var popularSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(popular))
	for _, n := range popular {
		m[n] = struct{}{}
	}
	return m
}()

// Check walks package.json files under target and returns suspected
// typosquats using the default distance threshold. Convenience wrapper.
func Check(target string) ([]Hit, error) {
	return CheckWith(target, DefaultMaxDistance)
}

// CheckWith is Check with a caller-specified max edit distance. Distance 1
// catches unambiguous single-typo squats; distance 2 raises false-positive
// rates significantly (see DefaultMaxDistance comment).
func CheckWith(target string, maxDistance int) ([]Hit, error) {
	if maxDistance < 1 {
		maxDistance = DefaultMaxDistance
	}
	var hits []Hit
	err := filepath.WalkDir(target, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "node_modules" || name == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != "package.json" {
			return nil
		}
		fileHits, err := scanFile(path, maxDistance)
		if err != nil {
			return nil
		}
		hits = append(hits, fileHits...)
		return nil
	})
	return hits, err
}

func scanFile(path string, maxDistance int) ([]Hit, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pj struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(raw, &pj); err != nil {
		return nil, err
	}
	sections := []struct {
		name string
		deps map[string]string
	}{
		{"dependencies", pj.Dependencies},
		{"devDependencies", pj.DevDependencies},
		{"peerDependencies", pj.PeerDependencies},
		{"optionalDependencies", pj.OptionalDependencies},
	}
	seen := make(map[string]struct{})
	var hits []Hit
	for _, sect := range sections {
		for name := range sect.deps {
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			if h, ok := classifyAt(name, maxDistance); ok {
				h.Source = path
				h.Section = sect.name
				hits = append(hits, h)
			}
		}
	}
	return hits, nil
}

// classify uses the default distance. Kept as a wrapper because tests call it.
func classify(name string) (Hit, bool) {
	return classifyAt(name, DefaultMaxDistance)
}

func classifyAt(name string, maxDistance int) (Hit, bool) {
	if len(name) < 4 {
		return Hit{}, false
	}
	if _, popular := popularSet[name]; popular {
		return Hit{}, false
	}
	best := Hit{Name: name, Distance: maxDistance + 1}
	for _, p := range popular {
		if abs(len(p)-len(name)) > maxDistance {
			continue
		}
		d := levenshtein(name, p)
		if d == 0 || d > maxDistance {
			continue
		}
		if d < best.Distance {
			best = Hit{Name: name, Confused: p, Distance: d}
			if d == 1 {
				break
			}
		}
	}
	if best.Confused == "" {
		return Hit{}, false
	}
	return best, true
}

// levenshtein computes edit distance between two strings.
// Standard two-row dynamic programming, byte-level (ASCII npm names).
func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
