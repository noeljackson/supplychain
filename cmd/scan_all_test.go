package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noeljackson/supplychain/internal/update"
)

func TestScanAllRejectsMissingRoot(t *testing.T) {
	g := &Globals{NoUpdate: true, DataDir: t.TempDir(), BinDir: t.TempDir()}
	if got := cmdScanAll(g, []string{filepath.Join(t.TempDir(), "missing")}); got != 3 {
		t.Fatalf("cmdScanAll exit = %d, want 3", got)
	}
}

func TestScanAllRejectsFileRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	g := &Globals{NoUpdate: true, DataDir: t.TempDir(), BinDir: t.TempDir()}
	if got := cmdScanAll(g, []string{path}); got != 3 {
		t.Fatalf("cmdScanAll exit = %d, want 3", got)
	}
}

func TestScanAllFailsWhenRepositoryScanErrors(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dataDir, "iocs", "packages.txt"), 0o700); err != nil {
		t.Fatal(err)
	}
	g := &Globals{
		NoUpdate: true,
		DataDir:  dataDir,
		BinDir:   t.TempDir(),
	}
	if got := cmdScanAll(g, []string{root}); got != 3 {
		t.Fatalf("cmdScanAll exit = %d, want 3", got)
	}
}

func TestScanAllRejectsExtraArguments(t *testing.T) {
	if got := cmdScanAll(&Globals{}, []string{".", "extra"}); got != 2 {
		t.Fatalf("cmdScanAll exit = %d, want 2", got)
	}
}

func TestFindGitReposReturnsRootTraversalError(t *testing.T) {
	_, err := findGitRepos(filepath.Join(t.TempDir(), "missing"))
	if err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("expected traversal error, got %v", err)
	}
}

func TestFindGitReposPropagatesUnreadableEntry(t *testing.T) {
	expected := &fs.PathError{
		Op:   "readdir",
		Path: "/fixture/unreadable",
		Err:  fs.ErrPermission,
	}
	previous := walkGitDirectories
	walkGitDirectories = func(string, fs.WalkDirFunc) error { return expected }
	t.Cleanup(func() { walkGitDirectories = previous })

	if _, err := findGitRepos("/fixture"); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("expected unreadable-entry error, got %v", err)
	}
}

func TestScanAllJSONEmitsOneDocument(t *testing.T) {
	root := t.TempDir()
	globals := &Globals{
		JSON:     true,
		NoUpdate: true,
		DataDir:  t.TempDir(),
		BinDir:   t.TempDir(),
	}
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	code := cmdScanAll(globals, []string{root})
	_ = writer.Close()
	os.Stdout = original
	t.Cleanup(func() { os.Stdout = original })
	if code != 3 {
		t.Fatalf("exit = %d, want operational 3", code)
	}
	decoder := json.NewDecoder(reader)
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("expected exactly one JSON document, got trailing value/error %v", err)
	}
	if document["command"] != "scan-all" {
		t.Fatalf("unexpected document: %v", document)
	}
}

func TestScanAllStrictFailsForOneIncompleteRepositoryAmongClean(t *testing.T) {
	root := t.TempDir()
	clean := filepath.Join(root, "clean")
	broken := filepath.Join(root, "broken")
	for _, repo := range []string{clean, broken} {
		if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(broken, "package.json"), []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	osvHelper := filepath.Join(binDir, "osv-scanner")
	if err := os.WriteFile(osvHelper, []byte(
		"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'fixture 1.0.0'; else echo '{\"results\":[]}'; fi\n",
	), 0o755); err != nil {
		t.Fatal(err)
	}
	globals := &Globals{
		NoUpdate:       true,
		FailOnAdvisory: true,
		DataDir:        writeCmdIOCFixture(t),
		BinDir:         binDir,
	}
	if code := cmdScanAll(globals, []string{root}); code != 3 {
		t.Fatalf("strict mixed scan exit = %d, want operational 3", code)
	}
}

func TestScanAllStrictFailsWhenOSVUnavailable(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	globals := &Globals{
		NoUpdate:       true,
		FailOnAdvisory: true,
		DataDir:        writeCmdIOCFixture(t),
		BinDir:         t.TempDir(),
	}
	if code := cmdScanAll(globals, []string{root}); code != 3 {
		t.Fatalf("strict unavailable-OSV exit = %d, want operational 3", code)
	}
}

func writeCmdIOCFixture(t *testing.T) string {
	t.Helper()
	dataDir := t.TempDir()
	iocDir := filepath.Join(dataDir, "iocs")
	if err := os.MkdirAll(iocDir, 0o700); err != nil {
		t.Fatal(err)
	}
	type manifestFile struct {
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	}
	document := struct {
		SchemaVersion  int                     `json:"schema_version"`
		GeneratedAt    string                  `json:"generated_at"`
		SourceRevision string                  `json:"source_revision"`
		Files          map[string]manifestFile `json:"files"`
	}{
		SchemaVersion:  1,
		GeneratedAt:    "2026-07-25T00:00:00Z",
		SourceRevision: "fixture",
		Files:          make(map[string]manifestFile),
	}
	for _, name := range update.IOCFiles {
		body := []byte("fixture-entry\n")
		if name == "packages.txt" {
			body = []byte("harmless@9.9.9\n")
		}
		if err := os.WriteFile(filepath.Join(iocDir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		document.Files[name] = manifestFile{
			SHA256: hex.EncodeToString(digest[:]),
			Size:   int64(len(body)),
		}
	}
	manifest, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(iocDir, "manifest.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	return dataDir
}
