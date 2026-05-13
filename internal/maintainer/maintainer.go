// Package maintainer detects changes to a package's maintainer set since the
// last scan. Most npm worms begin with a compromised maintainer account; if
// a previously-known package suddenly has a new (or fewer) maintainer(s),
// that's worth surfacing for review.
//
// First scan establishes a baseline silently. Subsequent scans diff against
// the baseline; deltas emit hits AND update the baseline so each change is
// reported once.
package maintainer

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/noeljackson/supplychain/internal/registry"
)

// Hit is one package whose maintainer set changed since the cached baseline.
type Hit struct {
	Name    string   `json:"name"`
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
	Current []string `json:"current"`
}

type baseline struct {
	Name        string    `json:"name"`
	Maintainers []string  `json:"maintainers"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Check walks installed deps under target and reports maintainer-set changes
// per unique package name (not version). Returns nil when reg is nil.
//
// Side effect: writes/updates baselines under baselineDir. First-time
// observations are silent (no findings) but DO write a baseline.
func Check(target string, reg *registry.Client, baselineDir string) ([]Hit, error) {
	if reg == nil {
		return nil, nil
	}
	if err := os.MkdirAll(baselineDir, 0o755); err != nil {
		return nil, err
	}

	names, err := installedPackageNames(target)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, nil
	}

	const workers = 8
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var hits []Hit

	for _, name := range names {
		name := name
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			p, err := reg.Get(name)
			if err != nil {
				return
			}
			current := maintainersToStrings(p.Maintainers)
			if len(current) == 0 {
				return // some packages have no maintainers field (e.g. unpublished)
			}

			bl, err := loadBaseline(baselineDir, name)
			if err != nil {
				_ = saveBaseline(baselineDir, name, current)
				return
			}

			added, removed := diffSets(bl.Maintainers, current)
			if len(added) == 0 && len(removed) == 0 {
				return
			}
			mu.Lock()
			hits = append(hits, Hit{
				Name:    name,
				Added:   added,
				Removed: removed,
				Current: current,
			})
			mu.Unlock()
			_ = saveBaseline(baselineDir, name, current)
		}()
	}
	wg.Wait()

	sort.Slice(hits, func(i, j int) bool { return hits[i].Name < hits[j].Name })
	return hits, nil
}

func maintainersToStrings(ms []registry.Maintainer) []string {
	out := make([]string, 0, len(ms))
	seen := make(map[string]struct{}, len(ms))
	for _, m := range ms {
		key := m.Name
		if key == "" {
			key = m.Email
		}
		if key == "" {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func diffSets(prev, curr []string) (added, removed []string) {
	prevSet := make(map[string]struct{}, len(prev))
	for _, p := range prev {
		prevSet[p] = struct{}{}
	}
	currSet := make(map[string]struct{}, len(curr))
	for _, c := range curr {
		currSet[c] = struct{}{}
	}
	for _, c := range curr {
		if _, ok := prevSet[c]; !ok {
			added = append(added, c)
		}
	}
	for _, p := range prev {
		if _, ok := currSet[p]; !ok {
			removed = append(removed, p)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func baselinePath(dir, name string) string {
	h := sha1.Sum([]byte(name))
	return filepath.Join(dir, hex.EncodeToString(h[:])+".json")
}

func loadBaseline(dir, name string) (*baseline, error) {
	b, err := os.ReadFile(baselinePath(dir, name))
	if err != nil {
		return nil, err
	}
	var bl baseline
	if err := json.Unmarshal(b, &bl); err != nil {
		return nil, err
	}
	return &bl, nil
}

func saveBaseline(dir, name string, maintainers []string) error {
	bl := baseline{Name: name, Maintainers: maintainers, UpdatedAt: time.Now()}
	b, err := json.Marshal(bl)
	if err != nil {
		return err
	}
	return os.WriteFile(baselinePath(dir, name), b, 0o644)
}

// installedPackageNames returns the deduped set of package names with at
// least one installed copy under target.
func installedPackageNames(target string) ([]string, error) {
	seen := make(map[string]struct{})
	var nmDirs []string
	err := filepath.WalkDir(target, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if d.Name() == ".git" {
			return fs.SkipDir
		}
		if d.Name() == "node_modules" {
			nmDirs = append(nmDirs, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, nm := range nmDirs {
		entries, err := os.ReadDir(nm)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasPrefix(name, ".") {
				continue
			}
			if strings.HasPrefix(name, "@") {
				children, err := os.ReadDir(filepath.Join(nm, name))
				if err != nil {
					continue
				}
				for _, c := range children {
					if !c.IsDir() || strings.HasPrefix(c.Name(), ".") {
						continue
					}
					seen[name+"/"+c.Name()] = struct{}{}
				}
				continue
			}
			seen[name] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}
