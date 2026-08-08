package osv

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func init() {
	if os.Getenv("GO_WANT_OSV_TIMEOUT_HELPER") != "1" ||
		filepath.Base(os.Args[0]) != "osv-scanner" {
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("osv-scanner timeout fixture 1.0.0")
		os.Exit(0)
	}
	time.Sleep(time.Second)
	os.Exit(0)
}

func TestNoPackageSourcesExitIsRecognized(t *testing.T) {
	err := &exec.ExitError{Stderr: []byte("No package sources found, --help for usage information.\n")}
	if !isNoPackageSources(err) {
		t.Fatal("expected no-package-sources stderr to be recognized")
	}
	if errors.Is(err, ErrNoPackageSources) {
		t.Fatal("raw process error must not equal the public sentinel")
	}
}

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

func TestScanReportsTimeoutAsOperationalFailure(t *testing.T) {
	binDir := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(executable, filepath.Join(binDir, "osv-scanner")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GO_WANT_OSV_TIMEOUT_HELPER", "1")
	previousTimeout := scanTimeout
	scanTimeout = 20 * time.Millisecond
	t.Cleanup(func() { scanTimeout = previousTimeout })

	if _, err := Scan(binDir, t.TempDir(), false); err == nil ||
		!strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected explicit timeout failure, got %v", err)
	}
}

func TestScanArgsEnableAllOfflineGuards(t *testing.T) {
	args := strings.Join(scanArgs("/workspace", true), " ")
	for _, required := range []string{"--offline", "--offline-vulnerabilities", "--no-resolve"} {
		if !strings.Contains(args, required) {
			t.Fatalf("offline arguments missing %s: %s", required, args)
		}
	}
	if !strings.HasSuffix(args, " /workspace") {
		t.Fatalf("scan target must remain the final argument: %s", args)
	}
}

func TestScanArgsRemainOnlineByDefault(t *testing.T) {
	args := strings.Join(scanArgs("/workspace", false), " ")
	for _, offlineOnly := range []string{"--offline", "--offline-vulnerabilities", "--no-resolve"} {
		if strings.Contains(args, offlineOnly) {
			t.Fatalf("default arguments unexpectedly contain %s: %s", offlineOnly, args)
		}
	}
}

func TestParsePreservesSeverityAndFixMetadata(t *testing.T) {
	body := []byte(`{
	  "results": [{
	    "source": {"path": "package-lock.json"},
	    "packages": [{
	      "package": {"name": "demo", "version": "1.0.0", "ecosystem": "npm"},
	      "vulnerabilities": [{
	        "id": "GHSA-demo",
	        "database_specific": {"severity": "HIGH"},
	        "affected": [{"ranges": [{"events": [
	          {"introduced": "0"}, {"fixed": "1.2.0"}, {"fixed": "1.1.0"}
	        ]}]}]
	      }]
	    }]
	  }]
	}`)
	hits, err := parse(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || len(hits[0].Advisories) != 1 {
		t.Fatalf("unexpected findings: %+v", hits)
	}
	advisory := hits[0].Advisories[0]
	if advisory.Severity != "high" {
		t.Fatalf("severity = %q", advisory.Severity)
	}
	if strings.Join(advisory.FixedVersions, ",") != "1.1.0,1.2.0" {
		t.Fatalf("fixed versions = %v", advisory.FixedVersions)
	}
}

func FuzzParseOSVOutput(f *testing.F) {
	f.Add([]byte(`{"results":[]}`))
	f.Add([]byte(`{"results":[{"source":{"path":"package-lock.json"},"packages":[{"package":{"name":"demo","version":"1.0.0","ecosystem":"npm"},"vulnerabilities":[{"id":"GHSA-demo"}]}]}]}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 2*1024*1024 {
			t.Skip()
		}
		_, _ = parse(body)
	})
}
