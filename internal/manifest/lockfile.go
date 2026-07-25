package manifest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/noeljackson/supplychain/internal/bunverify"
	"github.com/noeljackson/supplychain/internal/ioc"
)

// LockHit is a (name, version) pair found in a lockfile that matches an IOC.
type LockHit struct {
	File    string `json:"file"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Reason  string `json:"reason,omitempty"` // "version-match" (default) or "name-blocked"
}

// ScanLockfiles walks root looking for known lockfile formats and reports IOC
// hits found in them.
//
// For package-lock.json we parse the JSON so we don't depend on the version
// appearing on the same line as the name (it's a multi-line format). For
// pnpm-lock.yaml, yarn.lock, and bun.lock the canonical entry has the
// package@version pair on one line, so a line-based regex is enough.
func ScanLockfiles(root string, iocs []ioc.PackageIOC, blockedNames []string) ([]LockHit, error) {
	if len(iocs) == 0 && len(blockedNames) == 0 {
		return nil, nil
	}
	needles := indexNeedles(iocs)
	blocked := make(map[string]struct{}, len(blockedNames))
	for _, n := range blockedNames {
		blocked[n] = struct{}{}
	}

	var hits []LockHit
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk lockfile path %s: %w", path, walkErr)
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
			fileHits, err = scanNpmLock(path, needles, blocked)
		case "pnpm-lock.yaml":
			fileHits, err = scanPnpmLock(path, needles, blocked)
		case "yarn.lock":
			fileHits, err = scanYarnLock(path, needles, blocked)
		case "bun.lock":
			fileHits, err = scanBunLock(path, needles, blocked)
		default:
			return nil
		}
		if err != nil {
			return fmt.Errorf("scan lockfile %s: %w", path, err)
		}
		hits = append(hits, fileHits...)
		return nil
	})
	return dedupeAndSortLockHits(hits), err
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
func scanNpmLock(path string, needles map[string]map[string]struct{}, blocked map[string]struct{}) ([]LockHit, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseNpmLock(b, path, needles, blocked)
}

func parseNpmLock(
	body []byte,
	path string,
	needles map[string]map[string]struct{},
	blocked map[string]struct{},
) ([]LockHit, error) {
	var doc struct {
		Packages     map[string]struct{ Version string } `json:"packages"`
		Dependencies map[string]npmV1Dep                 `json:"dependencies"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
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
		if _, bad := blocked[name]; bad {
			hits = append(hits, LockHit{File: path, Name: name, Version: entry.Version, Reason: "name-blocked"})
			continue
		}
		if versions, ok := needles[name]; ok {
			if _, bad := versions[entry.Version]; bad {
				hits = append(hits, LockHit{File: path, Name: name, Version: entry.Version, Reason: "version-match"})
			}
		}
	}
	for name, dep := range doc.Dependencies {
		walkV1(name, dep, needles, blocked, &hits, path)
	}
	return hits, nil
}

type npmV1Dep struct {
	Version      string              `json:"version"`
	Dependencies map[string]npmV1Dep `json:"dependencies"`
}

func walkV1(name string, dep npmV1Dep, needles map[string]map[string]struct{}, blocked map[string]struct{}, hits *[]LockHit, path string) {
	if _, bad := blocked[name]; bad {
		*hits = append(*hits, LockHit{File: path, Name: name, Version: dep.Version, Reason: "name-blocked"})
	} else if versions, ok := needles[name]; ok {
		if _, bad := versions[dep.Version]; bad {
			*hits = append(*hits, LockHit{File: path, Name: name, Version: dep.Version, Reason: "version-match"})
		}
	}
	for child, sub := range dep.Dependencies {
		walkV1(child, sub, needles, blocked, hits, path)
	}
}

type resolvedPackage struct {
	Name    string
	Version string
}

func scanPnpmLock(path string, needles map[string]map[string]struct{}, blocked map[string]struct{}) ([]LockHit, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	packages, err := parsePnpmLock(f)
	if err != nil {
		return nil, err
	}
	return matchResolvedPackages(path, packages, needles, blocked), nil
}

func parsePnpmLock(r io.Reader) ([]resolvedPackage, error) {
	var packages []resolvedPackage
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.HasSuffix(line, ":") {
			continue
		}
		key := unquoteLockToken(strings.TrimSuffix(line, ":"))
		if pkg, ok := parsePnpmPackageKey(key); ok {
			packages = append(packages, pkg)
		}
	}
	return packages, sc.Err()
}

func parsePnpmPackageKey(key string) (resolvedPackage, bool) {
	key = strings.TrimPrefix(strings.TrimSpace(key), "/")
	if index := strings.IndexByte(key, '('); index >= 0 {
		key = key[:index]
	}
	if name, version, ok := splitResolvedDescriptor(key); ok {
		return resolvedPackage{Name: name, Version: version}, true
	}
	// pnpm v5 and earlier used /name/version and /@scope/name/version keys.
	if index := strings.LastIndexByte(key, '/'); index > 0 && index < len(key)-1 {
		name, version := key[:index], key[index+1:]
		if strings.Contains(version, ".") {
			return resolvedPackage{Name: name, Version: version}, true
		}
	}
	return resolvedPackage{}, false
}

func scanYarnLock(path string, needles map[string]map[string]struct{}, blocked map[string]struct{}) ([]LockHit, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	packages, err := parseYarnLock(f)
	if err != nil {
		return nil, err
	}
	return matchResolvedPackages(path, packages, needles, blocked), nil
}

func parseYarnLock(r io.Reader) ([]resolvedPackage, error) {
	var (
		names    []string
		packages []resolvedPackage
	)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if len(raw) == len(strings.TrimLeft(raw, " \t")) && strings.HasSuffix(trimmed, ":") {
			names = parseYarnHeader(strings.TrimSuffix(trimmed, ":"))
			continue
		}
		if len(names) == 0 {
			continue
		}
		version, ok := parseYarnVersion(trimmed)
		if !ok {
			continue
		}
		for _, name := range names {
			packages = append(packages, resolvedPackage{Name: name, Version: version})
		}
		names = nil
	}
	return packages, sc.Err()
}

func parseYarnHeader(header string) []string {
	var names []string
	seen := make(map[string]struct{})
	for _, descriptor := range strings.Split(header, ",") {
		descriptor = unquoteLockToken(strings.TrimSpace(descriptor))
		name, _, ok := splitRequestedDescriptor(descriptor)
		if !ok || name == "__metadata" {
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}

func parseYarnVersion(line string) (string, bool) {
	var value string
	switch {
	case strings.HasPrefix(line, "version:"):
		value = strings.TrimSpace(strings.TrimPrefix(line, "version:"))
	case strings.HasPrefix(line, "version "):
		value = strings.TrimSpace(strings.TrimPrefix(line, "version "))
	default:
		return "", false
	}
	value = unquoteLockToken(value)
	return value, value != ""
}

func scanBunLock(path string, needles map[string]map[string]struct{}, blocked map[string]struct{}) ([]LockHit, error) {
	packages, issues, err := bunverify.ParseLockfile(path)
	if err != nil {
		return nil, err
	}
	if len(issues) > 0 {
		return nil, fmt.Errorf(
			"Bun lockfile contains unsupported source entry %s: %s",
			issues[0].Package,
			issues[0].Message,
		)
	}
	resolved := make([]resolvedPackage, 0, len(packages))
	for _, pkg := range packages {
		resolved = append(resolved, resolvedPackage{Name: pkg.Name, Version: pkg.Version})
	}
	return matchResolvedPackages(path, resolved, needles, blocked), nil
}

func matchResolvedPackages(
	path string,
	packages []resolvedPackage,
	needles map[string]map[string]struct{},
	blocked map[string]struct{},
) []LockHit {
	var hits []LockHit
	for _, pkg := range packages {
		if _, bad := blocked[pkg.Name]; bad {
			hits = append(hits, LockHit{
				File: path, Name: pkg.Name, Version: pkg.Version, Reason: "name-blocked",
			})
			continue
		}
		if versions, ok := needles[pkg.Name]; ok {
			if _, bad := versions[pkg.Version]; bad {
				hits = append(hits, LockHit{
					File: path, Name: pkg.Name, Version: pkg.Version, Reason: "version-match",
				})
			}
		}
	}
	return hits
}

func splitResolvedDescriptor(value string) (string, string, bool) {
	index := strings.LastIndex(value, "@")
	if index <= 0 || index == len(value)-1 {
		return "", "", false
	}
	return value[:index], value[index+1:], true
}

func splitRequestedDescriptor(value string) (string, string, bool) {
	index := strings.IndexByte(value, '@')
	if strings.HasPrefix(value, "@") {
		slash := strings.IndexByte(value, '/')
		if slash < 0 {
			return "", "", false
		}
		next := strings.IndexByte(value[slash+1:], '@')
		if next < 0 {
			return "", "", false
		}
		index = slash + 1 + next
	}
	if index <= 0 || index == len(value)-1 {
		return "", "", false
	}
	return value[:index], value[index+1:], true
}

func unquoteLockToken(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 &&
		((value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'')) {
		if value[0] == '"' {
			if unquoted, err := strconv.Unquote(value); err == nil {
				return unquoted
			}
		}
		return value[1 : len(value)-1]
	}
	return value
}

func dedupeAndSortLockHits(hits []LockHit) []LockHit {
	seen := make(map[string]struct{}, len(hits))
	out := make([]LockHit, 0, len(hits))
	for _, hit := range hits {
		key := hit.File + "\x00" + hit.Name + "\x00" + hit.Version + "\x00" + hit.Reason
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, hit)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].Reason < out[j].Reason
	})
	return out
}
