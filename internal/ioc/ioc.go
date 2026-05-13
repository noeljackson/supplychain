// Package ioc loads and matches indicator-of-compromise data.
package ioc

import (
	"bufio"
	"io"
	"io/fs"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// Opener abstracts both the embedded default FS and on-disk overrides.
// cmd.Globals satisfies this interface via openIOC.
type Opener interface {
	// openIOC returns either an override file (DataDir/iocs/<name>) if present,
	// or falls back to the embedded default.
}

// OpenFunc returns the IOC file for the given basename ("packages.txt", etc).
type OpenFunc func(name string) (fs.File, error)

// PackageIOC is one line of packages.txt: a name@version pair we treat as bad.
type PackageIOC struct {
	Name    string
	Version string
	// Parsed is the parsed semver of Version, if it parses. Used so we can
	// answer "does this manifest range include the bad version" semantically.
	Parsed *semver.Version
}

// LoadPackages reads packages.txt via the opener and returns parsed IOC entries.
// Comment lines (starting with #) and blank lines are ignored. Malformed lines
// are silently skipped — the data file is human-edited and we'd rather scan
// than fail loudly on a typo.
func LoadPackages(open OpenFunc) ([]PackageIOC, error) {
	f, err := open("packages.txt")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parsePackages(f)
}

func parsePackages(r io.Reader) ([]PackageIOC, error) {
	var out []PackageIOC
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		// Find the LAST '@' — scoped packages have one in the name (@scope/name).
		at := strings.LastIndex(line, "@")
		if at <= 0 {
			continue
		}
		name := line[:at]
		ver := line[at+1:]
		if name == "" || ver == "" {
			continue
		}
		p := PackageIOC{Name: name, Version: ver}
		if v, err := semver.NewVersion(ver); err == nil {
			p.Parsed = v
		}
		out = append(out, p)
	}
	return out, sc.Err()
}

// LoadList reads a one-per-line list file (persistence-paths.txt, payload-filenames.txt),
// stripping comments and blank lines.
func LoadList(open OpenFunc, name string) ([]string, error) {
	f, err := open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseList(f), nil
}

func parseList(r io.Reader) []string {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}
