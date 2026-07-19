package osv

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDownloadVerifiesDigest(t *testing.T) {
	body := []byte("reviewed binary")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()
	destination := filepath.Join(t.TempDir(), "osv-scanner")
	expected := fmt.Sprintf("%x", sha256.Sum256(body))
	if err := download(context.Background(), server.URL, destination, expected); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("download mismatch: %q", got)
	}
}

func TestDownloadRejectsDigestMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("tampered"))
	}))
	defer server.Close()
	destination := filepath.Join(t.TempDir(), "osv-scanner")
	err := download(context.Background(), server.URL, destination, strings.Repeat("0", 64))
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum rejection, got %v", err)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("rejected download remained on disk: %v", err)
	}
}

func TestLocatePrefersManagedBinDir(t *testing.T) {
	managed := t.TempDir()
	pathDir := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(executable, filepath.Join(managed, "osv-scanner")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(executable, filepath.Join(pathDir, "osv-scanner")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", pathDir)
	path, _, err := Locate(managed)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(managed, "osv-scanner") {
		t.Fatalf("managed tool did not win: %s", path)
	}
}
