package osv

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// cargoEntry is one [[package]] entry of a Cargo.lock.
type cargoEntry struct {
	name, version string
	registry      bool
}

// dropLocalCargoPackages removes crates.io findings for packages that a
// Cargo.lock records without a source. Cargo writes no source for path and
// workspace crates, which are built from the repository itself, so an advisory
// for a registry crate that happens to share the name does not apply to them.
//
// It removes a finding only when its lockfile is readable and the finding's
// exact name and version appear there without a source and never with one.
// Anything else, including an unreadable lockfile, keeps the finding.
func dropLocalCargoPackages(target string, vulns []PackageVuln) []PackageVuln {
	local := map[string]map[string]bool{}
	out := vulns[:0:0]
	for _, v := range vulns {
		if v.Ecosystem != "crates.io" || v.SourcePath == "" {
			out = append(out, v)
			continue
		}
		path := v.SourcePath
		if !filepath.IsAbs(path) {
			path = filepath.Join(target, path)
		}
		packages, ok := local[path]
		if !ok {
			packages = localCargoPackages(path)
			local[path] = packages
		}
		if packages[v.Name+"@"+v.Version] {
			continue
		}
		out = append(out, v)
	}
	return out
}

// localCargoPackages returns name@version for every entry that the lockfile
// at path records only without a source. It returns nil when the file cannot
// be read.
func localCargoPackages(path string) map[string]bool {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var entries []cargoEntry
	var current *cargoEntry
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") {
			if line == "[[package]]" {
				entries = append(entries, cargoEntry{})
				current = &entries[len(entries)-1]
			} else {
				current = nil
			}
			continue
		}
		if current == nil {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch strings.TrimSpace(key) {
		case "name":
			current.name = value
		case "version":
			current.version = value
		case "source":
			current.registry = true
		}
	}
	if scanner.Err() != nil {
		return nil
	}

	registry := map[string]bool{}
	for _, entry := range entries {
		if entry.registry {
			registry[entry.name+"@"+entry.version] = true
		}
	}
	local := map[string]bool{}
	for _, entry := range entries {
		key := entry.name + "@" + entry.version
		if entry.name != "" && !entry.registry && !registry[key] {
			local[key] = true
		}
	}
	return local
}
