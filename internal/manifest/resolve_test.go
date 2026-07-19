package manifest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/noeljackson/supplychain/internal/ioc"
	"github.com/noeljackson/supplychain/internal/registry"
)

// newMockRegistry stands up an HTTP test server that returns a fixed packument
// shape for one package, then returns a registry.Client wired to it.
func newMockRegistry(t *testing.T, pkgName string, publishedVersions []string) (*registry.Client, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		versions := map[string]any{}
		for _, v := range publishedVersions {
			versions[v] = map[string]any{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":     pkgName,
			"versions": versions,
			"time": map[string]any{
				"created":  time.Now().Format(time.RFC3339),
				"modified": time.Now().Format(time.RFC3339),
			},
			"dist-tags": map[string]string{"latest": publishedVersions[len(publishedVersions)-1]},
		})
	}))

	// Repoint Client at the test server by swapping its base URL.
	// registry.Client uses a fixed registry URL; the easiest way is to
	// substitute via http.Client transport that rewrites the host.
	cli := registry.NewClient(filepath.Join(t.TempDir(), "cache"))
	cli.HTTP = &http.Client{Transport: rewriteHost(srv.URL)}
	return cli, srv.Close
}

// rewriteHost is a RoundTripper that sends every request to the test server.
type rewriteHost string

func (r rewriteHost) RoundTrip(req *http.Request) (*http.Response, error) {
	u := string(r) + req.URL.Path
	if req.URL.RawQuery != "" {
		u += "?" + req.URL.RawQuery
	}
	newReq, _ := http.NewRequestWithContext(req.Context(), req.Method, u, req.Body)
	for k, v := range req.Header {
		newReq.Header[k] = v
	}
	return http.DefaultTransport.RoundTrip(newReq)
}

func TestResolveRange_PicksHighestPublished(t *testing.T) {
	reg, stop := newMockRegistry(t, "evil-pkg", []string{"1.0.0", "1.0.1", "1.1.0", "1.1.5", "2.0.0"})
	defer stop()
	v, err := resolveRange(reg, "evil-pkg", "^1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if v.String() != "1.1.5" {
		t.Errorf("^1.0.0 → %s, want 1.1.5", v)
	}
}

func TestResolveRange_SkipsPrereleases(t *testing.T) {
	reg, stop := newMockRegistry(t, "evil-pkg", []string{"1.0.0", "1.0.1", "1.1.0-beta.1", "1.1.0-rc.2"})
	defer stop()
	v, err := resolveRange(reg, "evil-pkg", "^1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if v.String() != "1.0.1" {
		t.Errorf("expected 1.0.1 (highest non-prerelease), got %s", v)
	}
}

func TestScanRepo_ResolvedBadFiresWhenMaxIsMalicious(t *testing.T) {
	// Scenario: registry still has the malicious 1.0.2 published (the
	// maintainer hasn't unpublished yet). Manifest declares ^1.0.0 →
	// npm install would actually pick up the malicious version.
	reg, stop := newMockRegistry(t, "evil-pkg", []string{"1.0.0", "1.0.1", "1.0.2"})
	defer stop()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"),
		[]byte(`{"name":"x","dependencies":{"evil-pkg":"^1.0.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	iocs := []ioc.PackageIOC{
		{Name: "evil-pkg", Version: "1.0.2", Parsed: mustVer(t, "1.0.2")},
	}
	hits, err := ScanRepo(dir, iocs, nil, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d: %+v", len(hits), hits)
	}
	h := hits[0]
	if h.Resolved != "1.0.2" {
		t.Errorf("Resolved = %q, want 1.0.2", h.Resolved)
	}
	if !h.ResolvedBad {
		t.Errorf("ResolvedBad = false, want true (registry max IS the malicious version)")
	}
}

func TestScanRepo_ResolvedSafeWhenMaxIsClean(t *testing.T) {
	// Scenario: maintainer unpublished the malicious 1.0.2 (real-world
	// post-incident state). Manifest declares ^1.0.0 → npm install picks
	// the highest still-published version (1.0.1), which is clean.
	reg, stop := newMockRegistry(t, "evil-pkg", []string{"1.0.0", "1.0.1"})
	defer stop()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"),
		[]byte(`{"name":"x","dependencies":{"evil-pkg":"^1.0.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	iocs := []ioc.PackageIOC{
		{Name: "evil-pkg", Version: "1.0.2", Parsed: mustVer(t, "1.0.2")},
	}
	hits, err := ScanRepo(dir, iocs, nil, reg)
	if err != nil {
		t.Fatal(err)
	}
	// Range ^1.0.0 still includes the IOC version 1.0.2, so we get a hit —
	// but resolution shows 1.0.1 (clean).
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d: %+v", len(hits), hits)
	}
	h := hits[0]
	if h.Resolved != "1.0.1" {
		t.Errorf("Resolved = %q, want 1.0.1", h.Resolved)
	}
	if h.ResolvedBad {
		t.Errorf("ResolvedBad = true, want false (npm install would pick the clean 1.0.1)")
	}
}

// mustVer is also defined in lockfile_test.go — keep them in sync.
// (Both are in package manifest so the same symbol is reused at test time.)

var _ = semver.NewVersion // keep import even if unused in this file
