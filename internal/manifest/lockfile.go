package manifest

import (
	"bufio"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/noeljackson/supplychain/internal/ioc"
)

// LockHit is a (name, version) pair found in a lockfile that matches an IOC.
type LockHit struct {
	File    string `json:"file"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ScanLockfiles walks root looking for known lockfile formats and reports IOC
// hits found in them.
//
// For package-lock.json we parse the JSON so we don't depend on the version
// appearing on the same line as the name (it's a multi-line format). For
// pnpm-lock.yaml, yarn.lock, and bun.lock the canonical entry has the
// package@version pair on one line, so a line-based regex is enough.
func ScanLockfiles(root string, iocs []ioc.PackageIOC) ([]LockHit, error) {
	if len(iocs) == 0 {
		return nil, nil
	}
	needles := indexNeedles(iocs)

	var hits []LockHit
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
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
		var (
			fileHits []LockHit
			err      error
		)
		switch d.Name() {
		case "package-lock.json":
			fileHits, err = scanNpmLock(path, needles)
		case "pnpm-lock.yaml", "yarn.lock", "bun.lock":
			fileHits, err = scanLineLockfile(path, needles)
		default:
			return nil
		}
		if err != nil {
			return nil
		}
		hits = append(hits, fileHits...)
		return nil
	})
	return hits, err
}

func indexNeedles(iocs []ioc.PackageIOC) map[string]map[string]struct{} {
	out := make(map[string]map[string]struct{}, len(iocs))
	for _, e := range iocs {
		if _, ok := out[e.Name]; !ok {
			out[e.Name] = make(map[string]struct{})
		}
		out[e.Name][e.Version] = struct{}{}
	}
	return out
}

// scanNpmLock parses package-lock.json. The schema we care about:
//
//	"packages": {
//	  "node_modules/<name>": { "version": "<ver>", ... },
//	  "node_modules/<name>/node_modules/<other>": { "version": "<ver>", ... }
//	}
//
// Older v1 lockfiles use "dependencies" recursively, which we also handle.
func scanNpmLock(path string, needles map[string]map[string]struct{}) ([]LockHit, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Packages     map[string]struct{ Version string }       `json:"packages"`
		Dependencies map[string]npmV1Dep                       `json:"dependencies"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}

	var hits []LockHit
	for key, entry := range doc.Packages {
		name := strings.TrimPrefix(key, "node_modules/")
		// nested node_modules/.../node_modules/<name> — take the last segment(s)
		if i := strings.LastIndex(name, "node_modules/"); i >= 0 {
			name = name[i+len("node_modules/"):]
		}
		if name == "" {
			continue
		}
		if versions, ok := needles[name]; ok {
			if _, bad := versions[entry.Version]; bad {
				hits = append(hits, LockHit{File: path, Name: name, Version: entry.Version})
			}
		}
	}
	for name, dep := range doc.Dependencies {
		walkV1(name, dep, needles, &hits, path)
	}
	return hits, nil
}

type npmV1Dep struct {
	Version      string              `json:"version"`
	Dependencies map[string]npmV1Dep `json:"dependencies"`
}

func walkV1(name string, dep npmV1Dep, needles map[string]map[string]struct{}, hits *[]LockHit, path string) {
	if versions, ok := needles[name]; ok {
		if _, bad := versions[dep.Version]; bad {
			*hits = append(*hits, LockHit{File: path, Name: name, Version: dep.Version})
		}
	}
	for child, sub := range dep.Dependencies {
		walkV1(child, sub, needles, hits, path)
	}
}

// scanLineLockfile handles formats where each (name, version) pair appears on
// a single line: pnpm-lock.yaml, yarn.lock, bun.lock.
func scanLineLockfile(path string, needles map[string]map[string]struct{}) ([]LockHit, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var hits []LockHit
	seen := make(map[string]struct{})

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // bun.lock can have huge lines
	for sc.Scan() {
		line := sc.Text()
		for name, versions := range needles {
			if !strings.Contains(line, name) {
				continue
			}
			for v := range versions {
				if !strings.Contains(line, v) {
					continue
				}
				// Dedup hits per (file, name, version)
				key := name + "\x00" + v
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				hits = append(hits, LockHit{File: path, Name: name, Version: v})
			}
		}
	}
	return hits, sc.Err()
}
