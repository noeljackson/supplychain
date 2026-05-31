// Package drift flags inconsistencies between a project's manifest
// (package.json) and its companion lockfile. Two patterns:
//
//   - "lockfile-out-of-range": the lockfile pins a version that doesn't
//     satisfy the manifest's declared range. Typically means someone
//     edited package.json without re-running install — CI and local
//     dev will diverge.
//
//   - "missing-from-lockfile": a dep is declared in the manifest but
//     absent from the lockfile entirely. The lockfile is stale.
//
// Supports package-lock.json and bun.lock. pnpm-lock.yaml / yarn.lock are
// recognised but skipped (no parser yet) rather than flagged wholesale —
// extending the parser map is the obvious follow-up.
package drift

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// Hit is one (declared dep, lockfile state) inconsistency.
type Hit struct {
	ManifestFile string `json:"manifest_file"`
	LockFile     string `json:"lock_file,omitempty"`
	Section      string `json:"section"`
	Name         string `json:"name"`
	Range        string `json:"manifest_range"`
	LockVersion  string `json:"lock_version,omitempty"` // empty if missing-from-lockfile
	Reason       string `json:"reason"`                 // see top-of-file
}

// ScanRepo walks root finding package.json files and reports drift
// against each one's companion lockfile (same directory only — we don't
// climb to parents because workspace setups put a manifest per package).
// Skips files without a recognised lockfile alongside them.
func ScanRepo(root string) ([]Hit, error) {
	var hits []Hit
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			n := d.Name()
			if n == "node_modules" || n == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != "package.json" {
			return nil
		}
		fileHits := scanManifest(path)
		hits = append(hits, fileHits...)
		return nil
	})
	return hits, err
}

func scanManifest(manifestPath string) []Hit {
	dir := filepath.Dir(manifestPath)

	lockfile, locked := pickLockfile(dir)
	if lockfile == "" {
		return nil
	}

	pj, err := readManifest(manifestPath)
	if err != nil {
		return nil
	}

	var hits []Hit
	for _, sect := range manifestSections(pj) {
		for name, spec := range sect.deps {
			if !isSemverRange(spec) {
				continue // workspace:, file:, github:, npm-aliased, etc.
			}
			lockedVer, present := locked[name]
			if !present {
				hits = append(hits, Hit{
					ManifestFile: manifestPath, LockFile: lockfile,
					Section: sect.name, Name: name, Range: spec,
					Reason: "missing-from-lockfile",
				})
				continue
			}
			c, err := semver.NewConstraint(spec)
			if err != nil {
				continue
			}
			v, err := semver.NewVersion(lockedVer)
			if err != nil {
				continue
			}
			if !c.Check(v) {
				hits = append(hits, Hit{
					ManifestFile: manifestPath, LockFile: lockfile,
					Section: sect.name, Name: name, Range: spec,
					LockVersion: lockedVer, Reason: "lockfile-out-of-range",
				})
			}
		}
	}
	return hits
}

type packageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

type section struct {
	name string
	deps map[string]string
}

func manifestSections(pj packageJSON) []section {
	return []section{
		{"dependencies", pj.Dependencies},
		{"devDependencies", pj.DevDependencies},
		{"peerDependencies", pj.PeerDependencies},
		{"optionalDependencies", pj.OptionalDependencies},
	}
}

func readManifest(path string) (packageJSON, error) {
	var pj packageJSON
	raw, err := os.ReadFile(path)
	if err != nil {
		return pj, err
	}
	err = json.Unmarshal(raw, &pj)
	return pj, err
}

// pickLockfile returns the (path, top-level name->version map) for the first
// parseable lockfile found alongside the manifest, or ("", nil) if none.
// Supports package-lock.json and bun.lock. Formats we can't parse yet
// (pnpm-lock.yaml, yarn.lock) are skipped — returning a nil map for them would
// make every declared dep look "missing-from-lockfile", which is a false
// positive, so we fall through and report no drift for those projects instead.
func pickLockfile(dir string) (string, map[string]string) {
	// bun.lock is checked before pnpm/yarn so a project carrying several
	// lockfiles still gets parsed drift rather than being skipped.
	candidates := []string{"package-lock.json", "bun.lock", "pnpm-lock.yaml", "yarn.lock"}
	for _, name := range candidates {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		switch name {
		case "package-lock.json":
			return p, parseNpmLock(p)
		case "bun.lock":
			return p, parseBunLock(p)
		default:
			// pnpm-lock.yaml / yarn.lock: no parser yet — skip rather than
			// emit false "missing" hits. (TODO: real parsers.)
			continue
		}
	}
	return "", nil
}

// parseBunLock returns the name → resolved version map from a bun.lock (the
// text/JSON format, lockfileVersion 1). Each entry in the "packages" object is
// an array whose first element is the "name@version" descriptor, e.g.
//
//	"packages": {
//	  "turbo":            ["turbo@2.9.16", "", { ... }, "sha512-..."],
//	  "@astrojs/compiler": ["@astrojs/compiler@2.13.1", "", {}, "sha512-..."]
//	}
//
// We index by name; when a package is present at multiple versions the last
// one wins, which is sufficient for presence checks and the common single-
// version case.
func parseBunLock(path string) map[string]string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	// bun.lock is JSONC: it carries trailing commas (",}" / ",]") that Go's
	// encoding/json rejects, so normalise before decoding.
	raw = stripJSONTrailingCommas(raw)
	var doc struct {
		Packages map[string]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	out := make(map[string]string, len(doc.Packages))
	for key, rawEntry := range doc.Packages {
		var arr []json.RawMessage
		if err := json.Unmarshal(rawEntry, &arr); err != nil || len(arr) == 0 {
			continue
		}
		var spec string
		if err := json.Unmarshal(arr[0], &spec); err != nil {
			continue
		}
		name, version, ok := splitBunSpec(spec)
		if !ok {
			continue
		}
		// Only the hoisted/top-level entry is keyed by the bare package name;
		// workspace- or nesting-specific resolutions use path-prefixed keys
		// ("pkg/dep", "ws/@scope/dep"). Record only the hoisted version, since
		// that's what a top-level declared dep actually resolves to. Without
		// this, a dep present at several versions would resolve by random map
		// order and spuriously look out-of-range.
		if key == name {
			out[name] = version
		}
	}
	return out
}

// stripJSONTrailingCommas removes structural trailing commas (the "," in ",}"
// and ",]") from a JSONC byte stream such as bun.lock. It is string-aware —
// commas inside quoted strings are left untouched — so it won't corrupt
// version ranges or integrity hashes.
func stripJSONTrailingCommas(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			out = append(out, c)
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				continue // drop the trailing comma
			}
		}
		out = append(out, c)
	}
	return out
}

// splitBunSpec splits a bun "name@version" descriptor into its parts, keeping
// the leading "@" of a scoped name intact (e.g. "@scope/name@1.2.3" ->
// "@scope/name", "1.2.3"). The split is on the LAST "@" so the scope's "@"
// isn't mistaken for the version separator.
func splitBunSpec(spec string) (string, string, bool) {
	at := strings.LastIndex(spec, "@")
	if at <= 0 || at == len(spec)-1 {
		return "", "", false // no version, or a bare scoped name
	}
	return spec[:at], spec[at+1:], true
}

// parseNpmLock returns the top-level dep name → resolved version map from
// a package-lock.json (v2+ schema with the "packages" object). Nested
// node_modules entries are skipped — we only care about the direct deps
// the manifest declared.
func parseNpmLock(path string) map[string]string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		// v1 fallback
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	out := make(map[string]string)
	for key, entry := range doc.Packages {
		// Top-level direct deps appear as "node_modules/<name>".
		// Nested ones as "node_modules/.../node_modules/<name>".
		// Filter to top-level only by requiring no inner node_modules/.
		const prefix = "node_modules/"
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		rest := strings.TrimPrefix(key, prefix)
		if strings.Contains(rest, "/node_modules/") {
			continue // nested
		}
		if rest == "" {
			continue
		}
		// rest is "<name>" or "@scope/<name>". Both are valid direct entries.
		out[rest] = entry.Version
	}
	// v1 fallback: if "packages" was empty, fall back to "dependencies".
	if len(out) == 0 {
		for name, entry := range doc.Dependencies {
			out[name] = entry.Version
		}
	}
	return out
}

// isSemverRange filters out manifest specs we can't compare against a pinned
// version: workspace protocols, file/URL aliases, git refs, npm-aliases.
func isSemverRange(spec string) bool {
	for _, prefix := range []string{"workspace:", "file:", "link:", "github:", "git+", "git://", "http:", "https:", "npm:"} {
		if strings.HasPrefix(spec, prefix) {
			return false
		}
	}
	if spec == "*" || spec == "x" || spec == "X" || spec == "latest" {
		return false
	}
	return true
}
