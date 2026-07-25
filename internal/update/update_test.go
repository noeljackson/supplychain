package update

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIOCsForceActivatesCompleteSnapshotAndRetainsPrevious(t *testing.T) {
	files, manifest := fixtureSnapshot(t)
	server := snapshotServer(files, manifest)
	defer server.Close()
	t.Setenv(envURL, server.URL)

	dataDir := t.TempDir()
	active := filepath.Join(dataDir, "iocs")
	if err := os.MkdirAll(active, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(active, "old-marker"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := IOCsForce(dataDir); err != nil {
		t.Fatal(err)
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(active, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	if _, err := os.Stat(filepath.Join(dataDir, "iocs.previous", "old-marker")); err != nil {
		t.Fatalf("previous snapshot not retained: %v", err)
	}
	if _, err := os.Stat(filepath.Join(active, manifestName)); err != nil {
		t.Fatalf("active manifest missing: %v", err)
	}
}

func TestIOCsForceLeavesActiveSnapshotUntouchedOnDigestFailure(t *testing.T) {
	files, manifest := fixtureSnapshot(t)
	files["packages.txt"] = []byte("tampered@9.9.9\n")
	server := snapshotServer(files, manifest)
	defer server.Close()
	t.Setenv(envURL, server.URL)

	dataDir := t.TempDir()
	active := filepath.Join(dataDir, "iocs")
	if err := os.MkdirAll(active, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(active, "marker"), []byte("last-known-good"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := IOCsForce(dataDir); err == nil {
		t.Fatal("expected digest mismatch")
	}
	got, err := os.ReadFile(filepath.Join(active, "marker"))
	if err != nil {
		t.Fatalf("active snapshot was replaced: %v", err)
	}
	if string(got) != "last-known-good" {
		t.Fatalf("active marker = %q", got)
	}
}

func TestIOCsForceLeavesActiveSnapshotUntouchedOnPartialResponse(t *testing.T) {
	files, manifest := fixtureSnapshot(t)
	delete(files, "payload-filenames.txt")
	server := snapshotServer(files, manifest)
	defer server.Close()
	t.Setenv(envURL, server.URL)

	dataDir := t.TempDir()
	active := filepath.Join(dataDir, "iocs")
	if err := os.MkdirAll(active, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(active, "marker"), []byte("last-known-good"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := IOCsForce(dataDir); err == nil {
		t.Fatal("expected partial snapshot failure")
	}
	body, err := os.ReadFile(filepath.Join(active, "marker"))
	if err != nil || string(body) != "last-known-good" {
		t.Fatalf("active snapshot changed: %q, %v", body, err)
	}
}

func TestIOCsForceRejectsSemanticallyEmptyFile(t *testing.T) {
	files, _ := fixtureSnapshot(t)
	files["packages.txt"] = []byte("# comments only\n")
	manifestDocument := snapshotManifest{
		SchemaVersion:  manifestV1,
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		SourceRevision: "empty-fixture",
		Files:          make(map[string]snapshotFile, len(files)),
	}
	for name, body := range files {
		digest := sha256.Sum256(body)
		manifestDocument.Files[name] = snapshotFile{
			SHA256: hex.EncodeToString(digest[:]),
			Size:   int64(len(body)),
		}
	}
	manifest, err := json.Marshal(manifestDocument)
	if err != nil {
		t.Fatal(err)
	}
	server := snapshotServer(files, manifest)
	defer server.Close()
	t.Setenv(envURL, server.URL)
	if err := IOCsForce(t.TempDir()); err == nil {
		t.Fatal("expected semantic empty-file rejection")
	}
}

func fixtureSnapshot(t *testing.T) (map[string][]byte, []byte) {
	t.Helper()
	files := make(map[string][]byte, len(IOCFiles))
	manifest := snapshotManifest{
		SchemaVersion:  manifestV1,
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		SourceRevision: "fixture-revision",
		Files:          make(map[string]snapshotFile, len(IOCFiles)),
	}
	for _, name := range IOCFiles {
		body := []byte("fixture-" + name + "\n")
		files[name] = body
		digest := sha256.Sum256(body)
		manifest.Files[name] = snapshotFile{
			SHA256: hex.EncodeToString(digest[:]),
			Size:   int64(len(body)),
		}
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return files, encoded
}

func snapshotServer(files map[string][]byte, manifest []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		name := filepath.Base(request.URL.Path)
		if name == manifestName {
			_, _ = w.Write(manifest)
			return
		}
		body, ok := files[name]
		if !ok {
			http.NotFound(w, request)
			return
		}
		_, _ = w.Write(body)
	}))
}
