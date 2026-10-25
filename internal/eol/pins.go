package eol

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Pin is one runtime, toolchain or base-image version a file selects.
type Pin struct {
	// Products are the candidate products. Exactly one entry, except for a
	// bare image-tag codename such as "bookworm", which is judged against
	// whichever of Debian and Ubuntu has a release of that codename.
	Products []string `json:"products"`
	Version  string   `json:"version"`
	Path     string   `json:"path"`
	Line     int      `json:"line"`
	Source   string   `json:"source"`
	// Floor marks a lower bound such as engines.node ">=20": only its release
	// cycle is judged, never how far it trails that cycle's newest release.
	Floor bool `json:"floor,omitempty"`
	// Codename pins are dropped when no candidate product has that codename.
	Codename bool `json:"codename,omitempty"`
	// Snapshot is a dated apt snapshot; Products is empty.
	Snapshot time.Time `json:"snapshot,omitempty"`
}

const maxPinFile = 1 << 20

// skippedDirs hold dependencies, build output or deliberate test fixtures.
var skippedDirs = map[string]bool{
	".git": true, "node_modules": true, "target": true, "vendor": true, "testdata": true,
}

// Discover returns every pin it can resolve under root, ordered by path and
// line. In a Git worktree it reads only tracked files, so build output and
// scratch checkouts are not judged; elsewhere it walks the tree. Dependency,
// build and test-fixture directories and symbolic links are skipped.
func Discover(root string) ([]Pin, error) {
	files, err := trackedFiles(root)
	if err != nil {
		files, err = walkFiles(root)
		if err != nil {
			return nil, err
		}
	}
	var pins []Pin
	for _, rel := range files {
		if skipped(rel) {
			continue
		}
		detect := detectorFor(rel, path.Base(rel))
		if detect == nil {
			continue
		}
		full := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Lstat(full)
		if err != nil || !info.Mode().IsRegular() {
			continue // deleted from the worktree, a link, or not a file
		}
		content, err := readPinFile(full)
		if err != nil {
			return nil, err
		}
		pins = append(pins, detect(rel, content)...)
	}
	sort.SliceStable(pins, func(i, j int) bool {
		if pins[i].Path != pins[j].Path {
			return pins[i].Path < pins[j].Path
		}
		return pins[i].Line < pins[j].Line
	})
	return pins, nil
}

func skipped(rel string) bool {
	parts := strings.Split(rel, "/")
	for _, part := range parts[:len(parts)-1] {
		if skippedDirs[part] {
			return true
		}
	}
	return false
}

// trackedFiles lists the files Git tracks under root, relative to root. It
// fails outside a Git worktree. Hooks never run for ls-files.
func trackedFiles(root string) ([]string, error) {
	output, err := exec.Command("git", "-C", root, "ls-files", "-z", "--cached").Output()
	if err != nil {
		return nil, err
	}
	var files []string
	for _, name := range strings.Split(string(output), "\x00") {
		if name != "" {
			files = append(files, name)
		}
	}
	return files, nil
}

func walkFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk %s: %w", current, walkErr)
		}
		if entry.IsDir() {
			if current != root && skippedDirs[entry.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	return files, err
}

func readPinFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxPinFile+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(content) > maxPinFile {
		return nil, nil
	}
	return content, nil
}

type detector func(rel string, content []byte) []Pin

func detectorFor(rel, name string) detector {
	lower := strings.ToLower(name)
	switch {
	case name == "go.mod" || name == "go.work":
		return goModPins
	case name == "package.json":
		return packageJSONPins
	case name == ".nvmrc" || name == ".node-version":
		return versionFilePins("nodejs")
	case name == ".python-version":
		return versionFilePins("python")
	case name == ".bun-version":
		return versionFilePins("bun")
	case name == ".tool-versions":
		return toolVersionsPins
	case name == "rust-toolchain.toml" || name == "rust-toolchain":
		return rustToolchainPins
	case isDockerfile(lower):
		return dockerfilePins
	case lower == "action.yml" || lower == "action.yaml":
		return actionPins
	case isWorkflow(rel):
		return workflowPins
	case lower == "sources.list" || strings.HasSuffix(lower, ".list") || strings.HasSuffix(lower, ".sources"):
		return snapshotPins
	case strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml"):
		// Kubernetes manifests, Compose files and other YAML name images too.
		return imageYAMLPins
	}
	return nil
}

func isDockerfile(lower string) bool {
	if strings.HasSuffix(lower, ".dockerignore") {
		return false
	}
	return lower == "dockerfile" || lower == "containerfile" ||
		strings.HasPrefix(lower, "dockerfile.") || strings.HasPrefix(lower, "containerfile.") ||
		strings.HasSuffix(lower, ".dockerfile") || strings.HasSuffix(lower, ".containerfile")
}

func isWorkflow(rel string) bool {
	lower := strings.ToLower(rel)
	if !strings.HasSuffix(lower, ".yml") && !strings.HasSuffix(lower, ".yaml") {
		return false
	}
	for _, dir := range []string{".github/workflows/", ".gitea/workflows/", ".gitea/scoped_workflows/", ".forgejo/workflows/"} {
		if strings.HasPrefix(lower, dir) || strings.Contains(lower, "/"+dir) {
			return true
		}
	}
	return false
}

func lines(content []byte) []string {
	var out []string
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 64*1024), maxPinFile)
	for scanner.Scan() {
		out = append(out, scanner.Text())
	}
	return out
}

func pin(product, version, rel string, line int, source string) Pin {
	return Pin{Products: []string{product}, Version: version, Path: rel, Line: line, Source: source}
}

var (
	goDirective        = regexp.MustCompile(`^go\s+([0-9][0-9A-Za-z.\-]*)\s*(?://.*)?$`)
	toolchainDirective = regexp.MustCompile(`^toolchain\s+go([0-9][0-9A-Za-z.\-]*)\s*(?://.*)?$`)
)

func goModPins(rel string, content []byte) []Pin {
	var pins []Pin
	for index, line := range lines(content) {
		line = strings.TrimSpace(line)
		if match := goDirective.FindStringSubmatch(line); match != nil {
			pins = append(pins, pin("go", match[1], rel, index+1, "go directive"))
		}
		if match := toolchainDirective.FindStringSubmatch(line); match != nil {
			pins = append(pins, pin("go", match[1], rel, index+1, "toolchain directive"))
		}
	}
	return pins
}

var versionToken = regexp.MustCompile(`[0-9]+(?:\.[0-9]+)*`)

func packageJSONPins(rel string, content []byte) []Pin {
	var manifest struct {
		Engines        map[string]string `json:"engines"`
		PackageManager string            `json:"packageManager"`
	}
	if json.Unmarshal(content, &manifest) != nil {
		return nil
	}
	text := lines(content)
	var pins []Pin
	for _, engine := range []struct{ key, product string }{{"node", "nodejs"}, {"bun", "bun"}} {
		value, ok := manifest.Engines[engine.key]
		if !ok {
			continue
		}
		floor := versionToken.FindString(value)
		if floor == "" {
			continue
		}
		line := lineAfter(text, `"engines"`, `"`+engine.key+`"`)
		found := pin(engine.product, floor, rel, line, fmt.Sprintf("engines.%s %q", engine.key, value))
		found.Floor = true
		pins = append(pins, found)
	}
	// Only Bun has end-of-life data; npm, pnpm and Yarn are not judged.
	if name, version, ok := strings.Cut(manifest.PackageManager, "@"); ok && name == "bun" {
		version, _, _ = strings.Cut(version, "+")
		pins = append(pins, pin("bun", version, rel, lineAfter(text, `"packageManager"`, ""),
			"packageManager "+manifest.PackageManager))
	}
	return pins
}

// lineAfter returns the 1-based line holding needle at or after the line
// holding anchor, or the anchor's line when needle is empty.
func lineAfter(text []string, anchor, needle string) int {
	for index, line := range text {
		if !strings.Contains(line, anchor) {
			continue
		}
		if needle == "" {
			return index + 1
		}
		for offset := index; offset < len(text); offset++ {
			if strings.Contains(text[offset], needle) {
				return offset + 1
			}
		}
	}
	return 0
}

func versionFilePins(product string) detector {
	return func(rel string, content []byte) []Pin {
		for index, line := range lines(content) {
			value := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
			if value == "" {
				continue
			}
			if version, ok := normalizeRequested(value); ok {
				return []Pin{pin(product, version, rel, index+1, filepath.Base(rel))}
			}
			return nil
		}
		return nil
	}
}

// normalizeRequested accepts "20", "v20.11.1", "3.12" or an LTS codename such
// as "lts/iron", and refuses aliases such as "node", "stable" or "lts/*".
func normalizeRequested(value string) (string, bool) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	if codename, ok := strings.CutPrefix(value, "lts/"); ok {
		if codename == "*" || codename == "" {
			return "", false
		}
		return codename, true
	}
	value = strings.TrimSuffix(strings.TrimSuffix(value, ".x"), ".*")
	if value == "" || value[0] < '0' || value[0] > '9' {
		return "", false
	}
	return value, true
}

var toolNames = map[string]string{
	"nodejs": "nodejs", "node": "nodejs", "golang": "go", "go": "go",
	"python": "python", "bun": "bun", "rust": "rust",
}

func toolVersionsPins(rel string, content []byte) []Pin {
	var pins []Pin
	for index, line := range lines(content) {
		fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(fields) < 2 {
			continue
		}
		product, ok := toolNames[fields[0]]
		if !ok {
			continue
		}
		if version, ok := normalizeRequested(fields[1]); ok {
			pins = append(pins, pin(product, version, rel, index+1, ".tool-versions "+fields[0]))
		}
	}
	return pins
}

var rustChannel = regexp.MustCompile(`^\s*channel\s*=\s*["']([^"']+)["']`)

func rustToolchainPins(rel string, content []byte) []Pin {
	text := lines(content)
	for index, line := range text {
		if match := rustChannel.FindStringSubmatch(line); match != nil {
			return rustPin(rel, index+1, match[1])
		}
	}
	// The legacy plain rust-toolchain file holds only the channel.
	if filepath.Base(rel) == "rust-toolchain" && len(text) > 0 && !strings.Contains(string(content), "[") {
		return rustPin(rel, 1, strings.TrimSpace(text[0]))
	}
	return nil
}

func rustPin(rel string, line int, channel string) []Pin {
	if channel == "" || channel[0] < '0' || channel[0] > '9' {
		return nil // stable, beta and nightly float
	}
	return []Pin{pin("rust", channel, rel, line, "toolchain channel")}
}

var (
	setupVersion  = regexp.MustCompile(`^\s*-?\s*(node|go|python|bun)-version:\s*(.+?)\s*$`)
	imageKey      = regexp.MustCompile(`^\s*-?\s*(?:image|container):\s*['"]?([^'"\s#{}]+)['"]?\s*(?:#.*)?$`)
	dockerUses    = regexp.MustCompile(`^\s*-?\s*uses:\s*['"]?docker://([^'"\s#]+)`)
	actionRuntime = regexp.MustCompile(`^\s*using:\s*['"]?node([0-9]+)['"]?\s*(?:#.*)?$`)
	setupProducts = map[string]string{"node": "nodejs", "go": "go", "python": "python", "bun": "bun"}
)

func workflowPins(rel string, content []byte) []Pin {
	var pins []Pin
	for index, line := range lines(content) {
		number := index + 1
		if match := setupVersion.FindStringSubmatch(line); match != nil {
			product := setupProducts[match[1]]
			for _, value := range scalarList(match[2]) {
				if version, ok := normalizeRequested(value); ok {
					pins = append(pins, pin(product, version, rel, number, match[1]+"-version"))
				}
			}
			continue
		}
		pins = append(pins, yamlImagePins(rel, number, line)...)
	}
	return pins
}

func actionPins(rel string, content []byte) []Pin {
	var pins []Pin
	for index, line := range lines(content) {
		if match := actionRuntime.FindStringSubmatch(line); match != nil {
			pins = append(pins, pin("nodejs", match[1], rel, index+1, "action runtime node"+match[1]))
			continue
		}
		pins = append(pins, yamlImagePins(rel, index+1, line)...)
	}
	return pins
}

func imageYAMLPins(rel string, content []byte) []Pin {
	var pins []Pin
	for index, line := range lines(content) {
		pins = append(pins, yamlImagePins(rel, index+1, line)...)
	}
	return pins
}

func yamlImagePins(rel string, line int, text string) []Pin {
	if match := dockerUses.FindStringSubmatch(text); match != nil {
		return imagePins(match[1], rel, line, "uses docker://")
	}
	if match := imageKey.FindStringSubmatch(text); match != nil {
		reference := strings.TrimPrefix(match[1], "docker://")
		if reference == "Dockerfile" || strings.Contains(reference, "$") {
			return nil
		}
		return imagePins(reference, rel, line, "image")
	}
	return nil
}

// scalarList reads a YAML scalar or a one-line flow sequence of scalars.
func scalarList(value string) []string {
	value = strings.TrimSpace(strings.SplitN(value, " #", 2)[0])
	if strings.Contains(value, "${{") {
		return nil
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		var out []string
		for _, item := range strings.Split(value[1:len(value)-1], ",") {
			out = append(out, strings.Trim(strings.TrimSpace(item), `'"`))
		}
		return out
	}
	return []string{strings.Trim(value, `'"`)}
}

var aptSnapshot = regexp.MustCompile(`snapshot\.(?:debian\.org|ubuntu\.com)/[^\s'"]*?([0-9]{8}T[0-9]{6}Z)`)

func snapshotPins(rel string, content []byte) []Pin {
	var pins []Pin
	for index, line := range lines(content) {
		pins = append(pins, snapshotLinePins(rel, index+1, line)...)
	}
	return pins
}

func snapshotLinePins(rel string, line int, text string) []Pin {
	var pins []Pin
	seen := map[string]bool{}
	for _, match := range aptSnapshot.FindAllStringSubmatch(text, -1) {
		if seen[match[1]] {
			continue
		}
		seen[match[1]] = true
		moment, err := time.Parse("20060102T150405Z", match[1])
		if err != nil {
			continue
		}
		pins = append(pins, Pin{Version: match[1], Path: rel, Line: line, Source: "apt snapshot", Snapshot: moment})
	}
	return pins
}
