// Package freshness flags installed dependencies whose version was published
// in the last N days. Catches the common pattern of account-takeover attacks:
// attacker publishes a malicious version, victims install it before the
// community has time to disclose.
package freshness

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/noeljackson/supplychain/internal/registry"
)

// Hit is a single dep whose installed version is younger than the window.
type Hit struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Published time.Time `json:"published"`
	AgeHuman  string    `json:"age_human"`
}

// Check walks node_modules under target and reports deps whose installed
// version was published within `days` (default 7) of now. Returns nil when
// days <= 0 — callers can guard the check off via a flag.
func Check(target string, days int, reg *registry.Client) ([]Hit, error) {
	if days <= 0 || reg == nil {
		return nil, nil
	}
	deps, err := walkInstalled(target)
	if err != nil {
		return nil, err
	}
	if len(deps) == 0 {
		return nil, nil
	}

	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)

	const workers = 8
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var hits []Hit

	for _, d := range deps {
		d := d
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			p, err := reg.Get(d.Name)
			if err != nil {
				return
			}
			t, ok := p.Time[d.Version]
			if !ok || t.IsZero() {
				return
			}
			if t.After(cutoff) {
				mu.Lock()
				hits = append(hits, Hit{
					Name:      d.Name,
					Version:   d.Version,
					Published: t,
					AgeHuman:  ageHuman(t),
				})
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	sort.Slice(hits, func(i, j int) bool { return hits[i].Published.After(hits[j].Published) })
	return hits, nil
}

func ageHuman(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// dep is a minimal (name, version) pair from an installed package.json.
type dep struct{ Name, Version string }

func walkInstalled(target string) ([]dep, error) {
	var nmDirs []string
	err := filepath.WalkDir(target, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
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

	seen := make(map[string]struct{})
	var out []dep
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
					addDep(filepath.Join(nm, name, c.Name(), "package.json"), &out, seen)
				}
				continue
			}
			addDep(filepath.Join(nm, name, "package.json"), &out, seen)
		}
	}
	return out, nil
}

func addDep(pjPath string, out *[]dep, seen map[string]struct{}) {
	raw, err := os.ReadFile(pjPath)
	if err != nil {
		return
	}
	var pj struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &pj); err != nil {
		return
	}
	if pj.Name == "" || pj.Version == "" {
		return
	}
	key := pj.Name + "@" + pj.Version
	if _, dup := seen[key]; dup {
		return
	}
	seen[key] = struct{}{}
	*out = append(*out, dep{Name: pj.Name, Version: pj.Version})
}
