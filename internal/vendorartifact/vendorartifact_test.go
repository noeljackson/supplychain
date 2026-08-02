package vendorartifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noeljackson/supplychain/internal/registry"
)

type fakeRegistry struct {
	version   registry.VerifiedVersion
	tarball   []byte
	verifyErr error
	fetchErr  error
}

func (f *fakeRegistry) VerifyVersion(name, version string) (registry.VerifiedVersion, error) {
	if name != f.version.Name || version != f.version.Version {
		return registry.VerifiedVersion{}, registry.ErrVersionMissing
	}
	return f.version, f.verifyErr
}

func (f *fakeRegistry) FetchTarball(rawURL, integrity string) ([]byte, error) {
	if rawURL != f.version.Tarball || integrity != f.version.Integrity {
		return nil, errors.New("unexpected tarball request")
	}
	return f.tarball, f.fetchErr
}

func TestVerifyCleanVendoredNPMMember(t *testing.T) {
	fixture := newFixture(t, []byte("canonical htmx"))
	result, err := Verify(fixture.root, fixture.registry)
	if err != nil {
		t.Fatal(err)
	}
	if result.Checked != 1 || len(result.Issues) != 0 {
		t.Fatalf("result = %+v", result)
	}
}

func TestVerifyReportsLocalAndRegistryDrift(t *testing.T) {
	fixture := newFixture(t, []byte("canonical htmx"))
	localPath := filepath.Join(fixture.root, filepath.FromSlash(fixture.entry.Path))
	if err := os.WriteFile(localPath, []byte("modified htmx"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(fixture.root, fixture.registry)
	if err != nil {
		t.Fatal(err)
	}
	assertIssueCodes(t, result.Issues,
		"vendored-bytes-mismatch",
		"vendored-digest-mismatch",
		"vendored-size-mismatch",
	)

	fixture = newFixture(t, []byte("canonical htmx"))
	fixture.registry.version.Integrity = integrity([]byte("different tarball"))
	result, err = Verify(fixture.root, fixture.registry)
	if err != nil {
		t.Fatal(err)
	}
	assertIssueCodes(t, result.Issues, "registry-integrity-drift")
}

func TestVerifyReportsInvalidSignatureAndRejectedTarball(t *testing.T) {
	fixture := newFixture(t, []byte("canonical htmx"))
	fixture.registry.verifyErr = registry.ErrSignatureInvalid
	result, err := Verify(fixture.root, fixture.registry)
	if err != nil {
		t.Fatal(err)
	}
	assertIssueCodes(t, result.Issues, "registry-verification-failed")

	fixture = newFixture(t, []byte("canonical htmx"))
	fixture.registry.fetchErr = registry.ErrTarballURLUnsafe
	result, err = Verify(fixture.root, fixture.registry)
	if err != nil {
		t.Fatal(err)
	}
	assertIssueCodes(t, result.Issues, "registry-tarball-rejected")
}

func TestVerifyTreatsNetworkFailureAsCoverageError(t *testing.T) {
	fixture := newFixture(t, []byte("canonical htmx"))
	fixture.registry.fetchErr = errors.New("network unavailable")
	if _, err := Verify(fixture.root, fixture.registry); err == nil ||
		!strings.Contains(err.Error(), "network unavailable") {
		t.Fatalf("expected network error, got %v", err)
	}
}

func TestExtractMemberRejectsHostileArchives(t *testing.T) {
	tests := []struct {
		name    string
		entries []tarEntry
		want    string
	}{
		{
			name:    "traversal",
			entries: []tarEntry{{name: "../escape", body: []byte("bad")}},
			want:    "unsafe path",
		},
		{
			name:    "symlink",
			entries: []tarEntry{{name: "package/link", kind: tar.TypeSymlink, link: "/etc/passwd"}},
			want:    "contains link",
		},
		{
			name: "duplicate",
			entries: []tarEntry{
				{name: "package/dist/app.js", body: []byte("one")},
				{name: "package/dist/app.js", body: []byte("two")},
			},
			want: "duplicate member",
		},
		{
			name:    "missing",
			entries: []tarEntry{{name: "package/dist/other.js", body: []byte("other")}},
			want:    "was not found",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := extractMember(makeTarball(t, test.entries), "dist/app.js")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestExtractMemberRejectsOversizedEntryBeforeAllocation(t *testing.T) {
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{
		Name: "package/dist/app.js", Mode: 0o600, Size: maxArtifactBytes + 1, Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	_ = tarWriter.Close()
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := extractMember(compressed.Bytes(), "dist/app.js")
	if err == nil || !strings.Contains(err.Error(), "exceeds 20 MiB") {
		t.Fatalf("error = %v", err)
	}
}

func TestManifestMustBeTrackedStrictAndContained(t *testing.T) {
	fixture := newFixture(t, []byte("canonical htmx"))
	manifestPath := filepath.Join(fixture.root, filepath.FromSlash(ManifestPath))
	git(t, fixture.root, "rm", "--cached", ManifestPath)
	if _, err := Verify(fixture.root, fixture.registry); err == nil || !strings.Contains(err.Error(), "manifest must be tracked") {
		t.Fatalf("expected tracked-manifest error, got %v", err)
	}

	fixture = newFixture(t, []byte("canonical htmx"))
	manifestPath = filepath.Join(fixture.root, filepath.FromSlash(ManifestPath))
	var decoded map[string]any
	body, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded["unknown"] = true
	body, err = json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(fixture.root, fixture.registry); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected strict-schema error, got %v", err)
	}
}

func TestManifestRejectsFloatingVersionsUnsafeNamesAndDuplicateBindings(t *testing.T) {
	base := NPMEntry{
		Package: "htmx.org", Version: "2.0.10", Member: "dist/htmx.min.js",
		Path: "vendor/htmx.min.js", Integrity: integrity([]byte("tarball")),
		Size: 1, SHA384: digestSHA384([]byte("x")),
	}
	tests := []struct {
		name   string
		mutate func(*Manifest)
		want   string
	}{
		{"floating version", func(m *Manifest) { m.NPM[0].Version = "^2.0.10" }, "version must be exact"},
		{"unsafe package", func(m *Manifest) { m.NPM[0].Package = "../htmx" }, "exact npm name"},
		{"control path", func(m *Manifest) { m.NPM[0].Path = "vendor/htmx\n.js" }, "normalized relative path"},
		{"duplicate path", func(m *Manifest) { m.NPM = append(m.NPM, m.NPM[0]) }, "duplicates local path"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := Manifest{SchemaVersion: 1, NPM: []NPMEntry{base}}
			test.mutate(&manifest)
			if err := validateManifest(manifest); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestLocalArtifactMustBeTrackedRegularFile(t *testing.T) {
	fixture := newFixture(t, []byte("canonical htmx"))
	localPath := filepath.Join(fixture.root, filepath.FromSlash(fixture.entry.Path))
	git(t, fixture.root, "rm", "--cached", fixture.entry.Path)
	if _, err := Verify(fixture.root, fixture.registry); err == nil || !strings.Contains(err.Error(), "local artifact must be tracked") {
		t.Fatalf("expected tracked-artifact error, got %v", err)
	}

	fixture = newFixture(t, []byte("canonical htmx"))
	localPath = filepath.Join(fixture.root, filepath.FromSlash(fixture.entry.Path))
	if err := os.Remove(localPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", localPath); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(fixture.root, fixture.registry); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("expected regular-file error, got %v", err)
	}
}

func TestLocalArtifactCannotEscapeThroughParentSymlink(t *testing.T) {
	fixture := newFixture(t, []byte("canonical htmx"))
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "htmx.min.js")
	if err := os.WriteFile(outsideFile, []byte("canonical htmx"), 0o600); err != nil {
		t.Fatal(err)
	}
	localPath := filepath.Join(fixture.root, filepath.FromSlash(fixture.entry.Path))
	if err := os.Remove(localPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Dir(localPath)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Dir(localPath)); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(fixture.root, fixture.registry); err == nil || !strings.Contains(err.Error(), "resolves outside target") {
		t.Fatalf("expected parent-symlink escape rejection, got %v", err)
	}
}

func TestMissingManifestIsNotApplicable(t *testing.T) {
	root := initGit(t)
	_, err := Verify(root, &fakeRegistry{})
	if !errors.Is(err, ErrNotApplicable) {
		t.Fatalf("error = %v", err)
	}
}

func TestTrackedMinifiedAssetRequiresManifestDeclaration(t *testing.T) {
	root := initGit(t)
	writeFile(t, filepath.Join(root, "web", "undeclared.min.js"), []byte("minified"))
	git(t, root, "add", "web/undeclared.min.js")
	result, err := Verify(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertIssueCodes(t, result.Issues, "undeclared-minified-web-asset")
}

func TestManifestCannotLeaveAnotherMinifiedAssetUndeclared(t *testing.T) {
	fixture := newFixture(t, []byte("canonical htmx"))
	writeFile(t, filepath.Join(fixture.root, "web", "second.min.js"), []byte("second"))
	git(t, fixture.root, "add", "web/second.min.js")
	result, err := Verify(fixture.root, fixture.registry)
	if err != nil {
		t.Fatal(err)
	}
	assertIssueCodes(t, result.Issues, "undeclared-minified-web-asset")
}

func TestTrackedRuntimeSourceCannotReferencePackageCDN(t *testing.T) {
	root := initGit(t)
	writeFile(t, filepath.Join(root, "web", "index.html"), []byte(
		`<script src="https://unpkg.com/htmx.org@2.0.10/dist/htmx.min.js"></script>`,
	))
	git(t, root, "add", "web/index.html")
	result, err := Verify(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertIssueCodes(t, result.Issues, "external-package-cdn-reference")
}

type fixture struct {
	root     string
	entry    NPMEntry
	registry *fakeRegistry
}

func newFixture(t *testing.T, artifact []byte) fixture {
	t.Helper()
	root := initGit(t)
	tarball := makeTarball(t, []tarEntry{{name: "package/dist/htmx.min.js", body: artifact}})
	entry := NPMEntry{
		Package:   "htmx.org",
		Version:   "2.0.10",
		Member:    "dist/htmx.min.js",
		Path:      "vendor/htmx.min.js",
		Integrity: integrity(tarball),
		Size:      int64(len(artifact)),
		SHA384:    digestSHA384(artifact),
	}
	manifest := Manifest{SchemaVersion: 1, NPM: []NPMEntry{entry}}
	manifestBody, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, filepath.FromSlash(ManifestPath)), manifestBody)
	writeFile(t, filepath.Join(root, filepath.FromSlash(entry.Path)), artifact)
	git(t, root, "add", ManifestPath, entry.Path)
	return fixture{
		root:  root,
		entry: entry,
		registry: &fakeRegistry{
			version: registry.VerifiedVersion{
				Name: entry.Package, Version: entry.Version, Integrity: entry.Integrity,
				Tarball:        "https://registry.npmjs.org/htmx.org/-/htmx.org-2.0.10.tgz",
				SignatureKeyID: "SHA256:test",
			},
			tarball: tarball,
		},
	}
}

type tarEntry struct {
	name string
	body []byte
	kind byte
	link string
}

func makeTarball(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		kind := entry.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		header := &tar.Header{
			Name: entry.name, Mode: 0o600, Size: int64(len(entry.body)), Typeflag: kind, Linkname: entry.link,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if len(entry.body) > 0 {
			if _, err := tarWriter.Write(entry.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func initGit(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	git(t, root, "init", "--quiet")
	return root
}

func git(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}

func writeFile(t *testing.T, filePath string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func integrity(body []byte) string {
	digest := sha512.Sum512(body)
	return "sha512-" + base64.StdEncoding.EncodeToString(digest[:])
}

func assertIssueCodes(t *testing.T, issues []Issue, expected ...string) {
	t.Helper()
	actual := make([]string, 0, len(issues))
	for _, issue := range issues {
		actual = append(actual, issue.Code)
	}
	if strings.Join(actual, ",") != strings.Join(expected, ",") {
		t.Fatalf("issue codes = %v, want %v (issues: %+v)", actual, expected, issues)
	}
}
