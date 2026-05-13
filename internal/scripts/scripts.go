// Package scripts walks installed node_modules and surfaces dependencies that
// declare preinstall/install/postinstall lifecycle scripts. These are how the
// vast majority of npm supply-chain payloads actually execute, so surfacing
// them is a high-leverage informational signal.
package scripts

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Hit is a single dependency whose package.json declares at least one of the
// install lifecycle hooks.
type Hit struct {
	Path    string            `json:"path"`
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Hooks   map[string]string `json:"hooks"`
}

var lifecycle = []string{"preinstall", "install", "postinstall"}

// ScanInstalled walks target for every `node_modules` directory and inspects
// each immediate child's package.json. Scoped packages (`@scope/name`) are
// descended into one extra level.
//
// Returns one Hit per unique (name, version) pair, deduped across hoisting.
// Returns an empty slice (not an error) when target has no node_modules.
func ScanInstalled(target string) ([]Hit, error) {
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

	var hits []Hit
	seen := make(map[string]struct{})

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
				// Scoped: enumerate children under @scope/.
				scopeDir := filepath.Join(nm, name)
				children, err := os.ReadDir(scopeDir)
				if err != nil {
					continue
				}
				for _, c := range children {
					if !c.IsDir() || strings.HasPrefix(c.Name(), ".") {
						continue
					}
					maybeAdd(filepath.Join(scopeDir, c.Name(), "package.json"), &hits, seen)
				}
				continue
			}
			maybeAdd(filepath.Join(nm, name, "package.json"), &hits, seen)
		}
	}
	return hits, nil
}

func maybeAdd(pjPath string, hits *[]Hit, seen map[string]struct{}) {
	h, ok := readHit(pjPath)
	if !ok {
		return
	}
	key := h.Name + "@" + h.Version
	if _, dup := seen[key]; dup {
		return
	}
	seen[key] = struct{}{}
	*hits = append(*hits, h)
}

func readHit(path string) (Hit, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Hit{}, false
	}
	var pj struct {
		Name    string            `json:"name"`
		Version string            `json:"version"`
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(raw, &pj); err != nil {
		return Hit{}, false
	}
	if len(pj.Scripts) == 0 {
		return Hit{}, false
	}
	hooks := make(map[string]string)
	for _, name := range lifecycle {
		if s, ok := pj.Scripts[name]; ok && strings.TrimSpace(s) != "" {
			hooks[name] = s
		}
	}
	if len(hooks) == 0 {
		return Hit{}, false
	}
	return Hit{Path: path, Name: pj.Name, Version: pj.Version, Hooks: hooks}, true
}
