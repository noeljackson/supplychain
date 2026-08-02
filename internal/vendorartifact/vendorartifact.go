// Package vendorartifact verifies repository-vendored files against exact,
// signed npm registry tarballs without executing package or repository code.
package vendorartifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	semver "github.com/Masterminds/semver/v3"
	"github.com/noeljackson/supplychain/internal/registry"
)

const (
	ManifestPath     = ".supplychain/vendor-artifacts.json"
	maxManifestBytes = 1024 * 1024
	maxArtifactBytes = 20 * 1024 * 1024
	maxArchiveBytes  = 200 * 1024 * 1024
)

var ErrNotApplicable = errors.New("vendorartifact: manifest not found")

type Registry interface {
	VerifyVersion(name, version string) (registry.VerifiedVersion, error)
	FetchTarball(rawURL, integrity string) ([]byte, error)
}

type Manifest struct {
	SchemaVersion int        `json:"schema_version"`
	NPM           []NPMEntry `json:"npm"`
}

type NPMEntry struct {
	Package   string `json:"package"`
	Version   string `json:"version"`
	Member    string `json:"member"`
	Path      string `json:"path"`
	Integrity string `json:"integrity"`
	Size      int64  `json:"size"`
	SHA384    string `json:"sha384"`
}

type Issue struct {
	Code    string `json:"code"`
	Package string `json:"package"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

type Result struct {
	Manifest string
	Checked  int
	Issues   []Issue
}

func Verify(target string, npm Registry) (Result, error) {
	result := Result{Manifest: filepath.Join(target, filepath.FromSlash(ManifestPath))}
	minifiedAssets, externalReferences, err := inspectTrackedWebFiles(target)
	if err != nil {
		return result, err
	}
	manifest, root, err := readManifest(target, result.Manifest)
	if err != nil {
		if !errors.Is(err, ErrNotApplicable) {
			return result, err
		}
		for _, assetPath := range minifiedAssets {
			result.Issues = append(result.Issues, Issue{
				Code: "undeclared-minified-web-asset", Path: assetPath,
				Message: "tracked minified browser asset is not bound to reviewed package provenance",
			})
		}
		result.Issues = append(result.Issues, externalReferences...)
		if len(result.Issues) == 0 {
			return result, ErrNotApplicable
		}
		return result, nil
	}
	if npm == nil {
		return result, errors.New("vendorartifact: npm registry client is required")
	}
	result.Checked = len(manifest.NPM)
	declared := make(map[string]struct{}, len(manifest.NPM))
	for _, entry := range manifest.NPM {
		declared[entry.Path] = struct{}{}
		issues, err := verifyEntry(root, entry, npm)
		if err != nil {
			return result, err
		}
		result.Issues = append(result.Issues, issues...)
	}
	for _, assetPath := range minifiedAssets {
		if _, ok := declared[assetPath]; ok {
			continue
		}
		result.Issues = append(result.Issues, Issue{
			Code: "undeclared-minified-web-asset", Path: assetPath,
			Message: "tracked minified browser asset is not bound to reviewed package provenance",
		})
	}
	result.Issues = append(result.Issues, externalReferences...)
	sort.Slice(result.Issues, func(i, j int) bool {
		if result.Issues[i].Package != result.Issues[j].Package {
			return result.Issues[i].Package < result.Issues[j].Package
		}
		if result.Issues[i].Path != result.Issues[j].Path {
			return result.Issues[i].Path < result.Issues[j].Path
		}
		return result.Issues[i].Code < result.Issues[j].Code
	})
	return result, nil
}

func inspectTrackedWebFiles(target string) ([]string, []Issue, error) {
	root, err := filepath.Abs(target)
	if err != nil {
		return nil, nil, fmt.Errorf("vendorartifact: resolve web scan target: %w", err)
	}
	gitRootOutput, err := exec.Command("git", "-C", root, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return nil, nil, nil
	}
	gitRoot := filepath.Clean(strings.TrimSpace(string(gitRootOutput)))
	targetRel, err := filepath.Rel(gitRoot, root)
	if err != nil || outside(targetRel) {
		return nil, nil, errors.New("vendorartifact: web scan target is outside its Git worktree")
	}
	pathspec := "."
	if targetRel != "." {
		pathspec = filepath.ToSlash(targetRel)
	}
	listOutput, err := exec.Command(
		"git", "-C", gitRoot, "ls-files", "-z", "--cached", "--", pathspec,
	).Output()
	if err != nil {
		return nil, nil, fmt.Errorf("vendorartifact: list tracked web files: %w", err)
	}
	var minified []string
	var external []Issue
	for _, raw := range bytes.Split(listOutput, []byte{0}) {
		if len(raw) == 0 {
			continue
		}
		repoRel := filepath.Clean(filepath.FromSlash(string(raw)))
		source := filepath.Join(gitRoot, repoRel)
		rel, err := filepath.Rel(root, source)
		if err != nil || outside(rel) {
			continue
		}
		slashRel := filepath.ToSlash(rel)
		lowerName := strings.ToLower(filepath.Base(rel))
		if strings.HasSuffix(lowerName, ".min.js") ||
			strings.HasSuffix(lowerName, ".min.mjs") ||
			strings.HasSuffix(lowerName, ".min.cjs") ||
			strings.HasSuffix(lowerName, ".min.css") {
			minified = append(minified, slashRel)
		}
		if !webSourceExtension(strings.ToLower(filepath.Ext(rel))) {
			continue
		}
		info, err := os.Lstat(source)
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxArtifactBytes {
			continue
		}
		body, err := os.ReadFile(source)
		if err != nil {
			return nil, nil, fmt.Errorf("vendorartifact: inspect tracked web file %s: %w", slashRel, err)
		}
		if containsPackageCDN(body) {
			external = append(external, Issue{
				Code: "external-package-cdn-reference", Path: slashRel,
				Message: "tracked runtime web source references a package CDN instead of a reviewed local artifact",
			})
		}
	}
	sort.Strings(minified)
	return minified, external, nil
}

func webSourceExtension(extension string) bool {
	switch extension {
	case ".html", ".htm", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".css", ".scss", ".sass", ".less":
		return true
	default:
		return false
	}
}

func containsPackageCDN(body []byte) bool {
	lower := bytes.ToLower(body)
	for _, marker := range [][]byte{
		[]byte("unpkg.com/"),
		[]byte("cdn.jsdelivr.net/npm/"),
		[]byte("esm.sh/"),
		[]byte("cdn.skypack.dev/"),
	} {
		if bytes.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func readManifest(target, manifestPath string) (Manifest, string, error) {
	var manifest Manifest
	root, err := filepath.Abs(target)
	if err != nil {
		return manifest, "", fmt.Errorf("vendorartifact: resolve target: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return manifest, "", fmt.Errorf("vendorartifact: resolve target links: %w", err)
	}
	info, err := os.Lstat(manifestPath)
	if errors.Is(err, os.ErrNotExist) {
		return manifest, realRoot, ErrNotApplicable
	}
	if err != nil {
		return manifest, "", fmt.Errorf("vendorartifact: inspect manifest: %w", err)
	}
	if !info.Mode().IsRegular() {
		return manifest, "", errors.New("vendorartifact: manifest must be a regular file, not a symlink")
	}
	if info.Size() > maxManifestBytes {
		return manifest, "", errors.New("vendorartifact: manifest exceeds 1 MiB")
	}
	realManifestPath, err := filepath.EvalSymlinks(manifestPath)
	if err != nil {
		return manifest, "", fmt.Errorf("vendorartifact: resolve manifest links: %w", err)
	}
	if rel, err := filepath.Rel(realRoot, realManifestPath); err != nil || outside(rel) {
		return manifest, "", errors.New("vendorartifact: manifest resolves outside target")
	}
	if err := requireTracked(realRoot, manifestPath, "manifest"); err != nil {
		return manifest, "", err
	}
	file, err := os.Open(manifestPath)
	if err != nil {
		return manifest, "", fmt.Errorf("vendorartifact: open manifest: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxManifestBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, "", fmt.Errorf("vendorartifact: parse manifest: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return manifest, "", errors.New("vendorartifact: manifest contains trailing JSON")
	}
	if err := validateManifest(manifest); err != nil {
		return manifest, "", err
	}
	return manifest, realRoot, nil
}

func validateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != 1 {
		return fmt.Errorf("vendorartifact: unsupported schema_version %d", manifest.SchemaVersion)
	}
	if len(manifest.NPM) == 0 {
		return errors.New("vendorartifact: npm entries must not be empty")
	}
	seenPaths := map[string]struct{}{}
	seenMembers := map[string]struct{}{}
	for index, entry := range manifest.NPM {
		label := fmt.Sprintf("vendorartifact: npm[%d]", index)
		if !validPackageName(entry.Package) {
			return fmt.Errorf("%s package must be an exact npm name", label)
		}
		if _, err := semver.StrictNewVersion(entry.Version); err != nil {
			return fmt.Errorf("%s version must be exact", label)
		}
		if !safeRelativeSlashPath(entry.Member) {
			return fmt.Errorf("%s member must be a normalized relative path", label)
		}
		if !safeRelativeSlashPath(entry.Path) {
			return fmt.Errorf("%s path must be a normalized relative path", label)
		}
		if !validIntegrity(entry.Integrity, "sha512-", 64) {
			return fmt.Errorf("%s integrity must be a SHA-512 SRI value", label)
		}
		if !validIntegrity(entry.SHA384, "sha384-", 48) {
			return fmt.Errorf("%s sha384 must be a SHA-384 SRI value", label)
		}
		if entry.Size <= 0 || entry.Size > maxArtifactBytes {
			return fmt.Errorf("%s size must be between 1 and %d bytes", label, maxArtifactBytes)
		}
		if _, duplicate := seenPaths[entry.Path]; duplicate {
			return fmt.Errorf("%s duplicates local path %q", label, entry.Path)
		}
		seenPaths[entry.Path] = struct{}{}
		memberKey := entry.Package + "@" + entry.Version + ":" + entry.Member
		if _, duplicate := seenMembers[memberKey]; duplicate {
			return fmt.Errorf("%s duplicates npm member %q", label, memberKey)
		}
		seenMembers[memberKey] = struct{}{}
	}
	return nil
}

func verifyEntry(root string, entry NPMEntry, npm Registry) ([]Issue, error) {
	label := entry.Package + "@" + entry.Version
	localPath := filepath.Join(root, filepath.FromSlash(entry.Path))
	local, localIssues, err := readLocalArtifact(root, localPath, entry, label)
	if err != nil {
		return nil, err
	}
	issues := append([]Issue(nil), localIssues...)

	version, err := npm.VerifyVersion(entry.Package, entry.Version)
	if err != nil {
		if errors.Is(err, registry.ErrVersionMissing) || errors.Is(err, registry.ErrSignatureInvalid) {
			return append(issues, Issue{
				Code: "registry-verification-failed", Package: label,
				Message: err.Error(),
			}), nil
		}
		return nil, fmt.Errorf("vendorartifact: verify %s registry metadata: %w", label, err)
	}
	if version.Integrity != entry.Integrity {
		return append(issues, Issue{
			Code: "registry-integrity-drift", Package: label,
			Message: "reviewed tarball integrity differs from current signed npm metadata",
		}), nil
	}
	tarball, err := npm.FetchTarball(version.Tarball, version.Integrity)
	if err != nil {
		if errors.Is(err, registry.ErrTarballURLUnsafe) ||
			errors.Is(err, registry.ErrTarballIntegrityMismatch) ||
			errors.Is(err, registry.ErrTarballTooLarge) {
			return append(issues, Issue{
				Code: "registry-tarball-rejected", Package: label,
				Message: err.Error(),
			}), nil
		}
		return nil, fmt.Errorf("vendorartifact: fetch %s tarball: %w", label, err)
	}
	member, err := extractMember(tarball, entry.Member)
	if err != nil {
		return append(issues, Issue{
			Code: "archive-member-rejected", Package: label, Path: entry.Member,
			Message: err.Error(),
		}), nil
	}
	if int64(len(member)) != entry.Size {
		issues = append(issues, Issue{
			Code: "registry-member-size-mismatch", Package: label, Path: entry.Member,
			Message: fmt.Sprintf("registry member is %d bytes; manifest pins %d", len(member), entry.Size),
		})
	}
	if digestSHA384(member) != entry.SHA384 {
		issues = append(issues, Issue{
			Code: "registry-member-digest-mismatch", Package: label, Path: entry.Member,
			Message: "registry member SHA-384 differs from the reviewed manifest",
		})
	}
	if local != nil && !bytes.Equal(local, member) {
		issues = append(issues, Issue{
			Code: "vendored-bytes-mismatch", Package: label, Path: entry.Path,
			Message: "checked-in artifact differs from the signed npm tarball member",
		})
	}
	return issues, nil
}

func readLocalArtifact(root, localPath string, entry NPMEntry, label string) ([]byte, []Issue, error) {
	if rel, err := filepath.Rel(root, localPath); err != nil || outside(rel) {
		return nil, nil, errors.New("vendorartifact: local artifact escapes target")
	}
	info, err := os.Lstat(localPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, []Issue{{
			Code: "vendored-artifact-missing", Package: label, Path: entry.Path,
			Message: "reviewed local artifact is missing",
		}}, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("vendorartifact: inspect local artifact: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, nil, errors.New("vendorartifact: local artifact must be a regular file, not a symlink")
	}
	realLocalPath, err := filepath.EvalSymlinks(localPath)
	if err != nil {
		return nil, nil, fmt.Errorf("vendorartifact: resolve local artifact links: %w", err)
	}
	if rel, err := filepath.Rel(root, realLocalPath); err != nil || outside(rel) {
		return nil, nil, errors.New("vendorartifact: local artifact resolves outside target")
	}
	if info.Size() > maxArtifactBytes {
		return nil, nil, errors.New("vendorartifact: local artifact exceeds 20 MiB")
	}
	if err := requireTracked(root, localPath, "local artifact"); err != nil {
		return nil, nil, err
	}
	body, err := os.ReadFile(localPath)
	if err != nil {
		return nil, nil, fmt.Errorf("vendorartifact: read local artifact: %w", err)
	}
	var issues []Issue
	if int64(len(body)) != entry.Size {
		issues = append(issues, Issue{
			Code: "vendored-size-mismatch", Package: label, Path: entry.Path,
			Message: fmt.Sprintf("checked-in artifact is %d bytes; manifest pins %d", len(body), entry.Size),
		})
	}
	if digestSHA384(body) != entry.SHA384 {
		issues = append(issues, Issue{
			Code: "vendored-digest-mismatch", Package: label, Path: entry.Path,
			Message: "checked-in artifact SHA-384 differs from the reviewed manifest",
		})
	}
	return body, issues, nil
}

func extractMember(tarball []byte, member string) ([]byte, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return nil, fmt.Errorf("open npm gzip stream: %w", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	wanted := "package/" + member
	var found []byte
	var total int64
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read npm tar archive: %w", err)
		}
		name := strings.TrimSuffix(header.Name, "/")
		if !safeRelativeSlashPath(name) {
			return nil, fmt.Errorf("npm archive contains unsafe path %q", header.Name)
		}
		if header.Size < 0 {
			return nil, fmt.Errorf("npm archive contains negative size for %q", header.Name)
		}
		if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
			return nil, fmt.Errorf("npm archive contains link %q", header.Name)
		}
		if header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA {
			if header.Size > maxArchiveBytes-total {
				return nil, errors.New("npm archive expands beyond 200 MiB")
			}
			total += header.Size
		}
		if name != wanted {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("npm archive contains duplicate member %q", wanted)
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return nil, fmt.Errorf("npm archive member %q is not a regular file", wanted)
		}
		if header.Size > maxArtifactBytes {
			return nil, fmt.Errorf("npm archive member %q exceeds 20 MiB", wanted)
		}
		found = make([]byte, header.Size)
		if _, err := io.ReadFull(tarReader, found); err != nil {
			return nil, fmt.Errorf("read npm archive member %q: %w", wanted, err)
		}
	}
	if found == nil {
		return nil, fmt.Errorf("npm archive member %q was not found", wanted)
	}
	return found, nil
}

func requireTracked(root, candidate, kind string) error {
	rel, err := filepath.Rel(root, candidate)
	if err != nil || outside(rel) {
		return fmt.Errorf("vendorartifact: %s must be inside the Git worktree", kind)
	}
	command := exec.Command("git", "-C", root, "ls-files", "--error-unmatch", "--", filepath.ToSlash(rel))
	command.Stdout = nil
	command.Stderr = nil
	if err := command.Run(); err != nil {
		return fmt.Errorf("vendorartifact: %s must be tracked by Git", kind)
	}
	return nil
}

func safeRelativeSlashPath(value string) bool {
	return value != "" &&
		!strings.Contains(value, "\\") &&
		!strings.ContainsFunc(value, unicode.IsControl) &&
		!strings.HasPrefix(value, "/") &&
		path.Clean(value) == value &&
		value != "." &&
		value != ".." &&
		!strings.HasPrefix(value, "../")
}

func validPackageName(value string) bool {
	if value == "" || len(value) > 214 || strings.ContainsFunc(value, unicode.IsControl) {
		return false
	}
	if strings.HasPrefix(value, "@") {
		parts := strings.Split(value[1:], "/")
		return len(parts) == 2 && validPackagePart(parts[0]) && validPackagePart(parts[1])
	}
	return !strings.Contains(value, "/") && validPackagePart(value)
}

func validPackagePart(value string) bool {
	if value == "" || value == "." || value == ".." || strings.HasPrefix(value, ".") || strings.HasPrefix(value, "_") {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("-._~", character) {
			continue
		}
		return false
	}
	return true
}

func outside(value string) bool {
	return value == ".." || strings.HasPrefix(value, ".."+string(filepath.Separator))
}

func validIntegrity(value, prefix string, size int) bool {
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && len(decoded) == size
}

func digestSHA384(body []byte) string {
	digest := sha512.Sum384(body)
	return "sha384-" + base64.StdEncoding.EncodeToString(digest[:])
}
