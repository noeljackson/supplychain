// Package manifest parses package.json files and matches their declared
// dependencies against IOC entries.
package manifest

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Masterminds/semver/v3"
	"github.com/noeljackson/supplychain/internal/ioc"
)

// PackageJSON is a minimal model of the parts of package.json we care about.
type PackageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// ManifestHit is a single dependency entry in a package.json that matches
// (or could resolve to) a known-bad package@version IOC.
type ManifestHit struct {
	File       string  // absolute path to the package.json
	Section    string  // dependencies | devDependencies | peerDependencies | optionalDependencies
	Name       string  // package name
	Range      string  // raw version spec from the manifest
	BadVersion string  // the IOC version that the range matches
	Reason     string  // "exact-match" | "range-includes" | "unknown-spec"
}

// ScanRepo walks `root` finding package.json files (skipping node_modules and
// .git), parses each, and returns matches against the provided IOC list and
// the blocked-names set (any version of a blocked name = hit).
func ScanRepo(root string, iocs []ioc.PackageIOC, blockedNames []string) ([]ManifestHit, error) {
	index := indexByName(iocs)
	blocked := indexSet(blockedNames)

	var hits []ManifestHit
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
		if d.Name() != "package.json" {
			return nil
		}
		fileHits, err := scanFile(path, index, blocked)
		if err != nil {
			return nil // malformed package.json — skip, don't abort scan
		}
		hits = append(hits, fileHits...)
		return nil
	})
	return hits, err
}

func indexSet(names []string) map[string]struct{} {
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		m[n] = struct{}{}
	}
	return m
}

func indexByName(iocs []ioc.PackageIOC) map[string][]ioc.PackageIOC {
	out := make(map[string][]ioc.PackageIOC, len(iocs))
	for _, e := range iocs {
		out[e.Name] = append(out[e.Name], e)
	}
	return out
}

func scanFile(path string, idx map[string][]ioc.PackageIOC, blocked map[string]struct{}) ([]ManifestHit, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pj PackageJSON
	if err := json.Unmarshal(raw, &pj); err != nil {
		return nil, err
	}

	var hits []ManifestHit
	for _, sect := range []struct {
		name string
		deps map[string]string
	}{
		{"dependencies", pj.Dependencies},
		{"devDependencies", pj.DevDependencies},
		{"peerDependencies", pj.PeerDependencies},
		{"optionalDependencies", pj.OptionalDependencies},
	} {
		for name, spec := range sect.deps {
			// Blocked-name match: any version is bad.
			if _, bad := blocked[name]; bad {
				hits = append(hits, ManifestHit{
					File:       path,
					Section:    sect.name,
					Name:       name,
					Range:      spec,
					BadVersion: "(any)",
					Reason:     "name-blocked",
				})
				continue
			}
			entries, ok := idx[name]
			if !ok {
				continue
			}
			for _, e := range entries {
				if hit := matchSpec(name, spec, e); hit != nil {
					hit.File = path
					hit.Section = sect.name
					hits = append(hits, *hit)
				}
			}
		}
	}
	return hits, nil
}

// matchSpec decides whether a manifest version spec (e.g. "^1.169.0", "1.169.5",
// "*", "workspace:*", "github:foo/bar") matches a known-bad version.
func matchSpec(name, spec string, bad ioc.PackageIOC) *ManifestHit {
	// Exact pin match.
	if spec == bad.Version {
		return &ManifestHit{
			Name:       name,
			Range:      spec,
			BadVersion: bad.Version,
			Reason:     "exact-match",
		}
	}
	// Semver range match — only meaningful if both sides parse.
	if bad.Parsed == nil {
		return nil
	}
	c, err := semver.NewConstraint(spec)
	if err != nil {
		// Specs we can't parse: "*", "workspace:*", git/file URLs, etc.
		// "*" technically matches everything but we don't want to flood on it;
		// only flag if the spec is genuinely a star.
		if spec == "*" || spec == "x" || spec == "X" {
			return &ManifestHit{
				Name:       name,
				Range:      spec,
				BadVersion: bad.Version,
				Reason:     "wildcard-spec",
			}
		}
		return nil
	}
	if c.Check(bad.Parsed) {
		return &ManifestHit{
			Name:       name,
			Range:      spec,
			BadVersion: bad.Version,
			Reason:     "range-includes",
		}
	}
	return nil
}

func (h ManifestHit) String() string {
	return fmt.Sprintf("%s@%s (declares %q) — %s in %s", h.Name, h.BadVersion, h.Range, h.Reason, h.Section)
}
