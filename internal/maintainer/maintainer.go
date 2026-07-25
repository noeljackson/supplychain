// Package maintainer detects changes to a package's maintainer set since the
// last scan. Most npm worms begin with a compromised maintainer account; if
// a previously-known package suddenly has a new (or fewer) maintainer(s),
// that's worth surfacing for review.
//
// Baselines advance only through explicit acceptance. Repository-tracked
// single-file baselines are preferred for CI; the per-package directory form
// remains available for local scans.
package maintainer

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/noeljackson/supplychain/internal/registry"
)

const (
	fileBaselineVersion = 1
	maxFileBaselineSize = 1024 * 1024
)

type fileBaseline struct {
	SchemaVersion int                 `json:"schema_version"`
	Packages      map[string][]string `json:"packages"`
}

// Hit is one package whose maintainer set changed since the cached baseline.
type Hit struct {
	Name    string   `json:"name"`
	Reason  string   `json:"reason"`
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
// Baselines are only written when accept is true. A missing baseline is a
// finding until the user explicitly reviews and accepts the current state.
func Check(target string, reg *registry.Client, baselineDir string, accept bool) ([]Hit, error) {
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
	var checkErr error

	for _, name := range names {
		name := name
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			p, err := reg.Get(name)
			if err != nil {
				mu.Lock()
				checkErr = errors.Join(checkErr, fmt.Errorf("registry metadata for %s: %w", name, err))
				mu.Unlock()
				return
			}
			current := maintainersToStrings(p.Maintainers)
			if len(current) == 0 {
				return // some packages have no maintainers field (e.g. unpublished)
			}

			bl, err := loadBaseline(baselineDir, name)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					if accept {
						if saveErr := saveBaseline(baselineDir, name, current); saveErr != nil {
							mu.Lock()
							checkErr = errors.Join(checkErr, saveErr)
							mu.Unlock()
						}
						return
					}
					mu.Lock()
					hits = append(hits, Hit{
						Name: name, Reason: "baseline-missing", Added: current, Current: current,
					})
					mu.Unlock()
					return
				}
				mu.Lock()
				checkErr = errors.Join(checkErr, fmt.Errorf("load maintainer baseline for %s: %w", name, err))
				mu.Unlock()
				return
			}

			added, removed := diffSets(bl.Maintainers, current)
			if len(added) == 0 && len(removed) == 0 {
				return
			}
			if accept {
				if saveErr := saveBaseline(baselineDir, name, current); saveErr != nil {
					mu.Lock()
					checkErr = errors.Join(checkErr, saveErr)
					mu.Unlock()
				}
				return
			}
			mu.Lock()
			hits = append(hits, Hit{
				Name:    name,
				Reason:  "maintainer-change",
				Added:   added,
				Removed: removed,
				Current: current,
			})
			mu.Unlock()
		}()
	}
	wg.Wait()

	sort.Slice(hits, func(i, j int) bool { return hits[i].Name < hits[j].Name })
	return hits, checkErr
}

// CheckFile uses one deterministic repository-tracked baseline. A missing
// baseline remains a finding until accept explicitly writes a review candidate.
func CheckFile(
	target string,
	reg *registry.Client,
	path string,
	accept bool,
) ([]Hit, error) {
	if reg == nil {
		return nil, nil
	}
	resolved, exists, err := resolveFileBaseline(target, path)
	if err != nil {
		return nil, err
	}
	previous := fileBaseline{
		SchemaVersion: fileBaselineVersion,
		Packages:      make(map[string][]string),
	}
	if exists {
		body, err := os.ReadFile(resolved)
		if err != nil {
			return nil, err
		}
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&previous); err != nil {
			return nil, fmt.Errorf("parse maintainer baseline: %w", err)
		}
		if previous.SchemaVersion != fileBaselineVersion || previous.Packages == nil {
			return nil, errors.New("unsupported or malformed maintainer baseline")
		}
	}
	names, err := installedPackageNames(target)
	if err != nil {
		return nil, err
	}
	current := make(map[string][]string, len(names))
	var hits []Hit
	for _, name := range names {
		packument, err := reg.Get(name)
		if err != nil {
			return nil, fmt.Errorf("registry metadata for %s: %w", name, err)
		}
		maintainers := maintainersToStrings(packument.Maintainers)
		if len(maintainers) == 0 {
			continue
		}
		current[name] = maintainers
		old, ok := previous.Packages[name]
		if !ok {
			hits = append(hits, Hit{
				Name: name, Reason: "baseline-missing", Added: maintainers, Current: maintainers,
			})
			continue
		}
		added, removed := diffSets(old, maintainers)
		if len(added) > 0 || len(removed) > 0 {
			hits = append(hits, Hit{
				Name: name, Reason: "maintainer-change", Added: added,
				Removed: removed, Current: maintainers,
			})
		}
	}
	if accept {
		if err := saveFileBaseline(resolved, current); err != nil {
			return nil, err
		}
		return nil, nil
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Name < hits[j].Name })
	return hits, nil
}

func resolveFileBaseline(target, path string) (string, bool, error) {
	if path == "" {
		return "", false, errors.New("maintainer baseline path is required")
	}
	target, err := filepath.Abs(target)
	if err != nil {
		return "", false, err
	}
	candidate := path
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(target, candidate)
	}
	candidate = filepath.Clean(candidate)
	relative, err := filepath.Rel(target, candidate)
	if err != nil || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return "", false, errors.New("maintainer baseline must be inside the scan target")
	}
	info, err := os.Lstat(candidate)
	if errors.Is(err, os.ErrNotExist) {
		return candidate, false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !info.Mode().IsRegular() {
		return "", false, errors.New("maintainer baseline must be a regular file, not a symlink")
	}
	if info.Size() > maxFileBaselineSize {
		return "", false, fmt.Errorf("maintainer baseline exceeds %d bytes", maxFileBaselineSize)
	}
	rootOutput, err := exec.Command("git", "-C", target, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", false, errors.New("maintainer baseline requires a Git worktree")
	}
	root := strings.TrimSpace(string(rootOutput))
	repoRelative, err := filepath.Rel(root, candidate)
	if err != nil || repoRelative == ".." ||
		strings.HasPrefix(repoRelative, ".."+string(os.PathSeparator)) {
		return "", false, errors.New("maintainer baseline is outside the Git worktree")
	}
	if err := exec.Command(
		"git", "-C", root, "ls-files", "--error-unmatch", "--",
		filepath.ToSlash(repoRelative),
	).Run(); err != nil {
		return "", false, errors.New("maintainer baseline must be tracked by Git")
	}
	return candidate, true, nil
}

func saveFileBaseline(path string, packages map[string][]string) error {
	document := fileBaseline{SchemaVersion: fileBaselineVersion, Packages: packages}
	body, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".maintainers-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
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
	tmp, err := os.CreateTemp(dir, ".maintainer-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, baselinePath(dir, name))
}

// installedPackageNames returns the deduped set of package names with at
// least one installed copy under target.
func installedPackageNames(target string) ([]string, error) {
	seen := make(map[string]struct{})
	var nmDirs []string
	err := filepath.WalkDir(target, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk installed package path %s: %w", path, walkErr)
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
			return nil, fmt.Errorf("read node_modules %s: %w", nm, err)
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
					return nil, fmt.Errorf("read package scope %s: %w", filepath.Join(nm, name), err)
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
