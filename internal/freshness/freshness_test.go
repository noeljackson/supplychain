package freshness

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noeljackson/supplychain/internal/registry"
)

// rewriteHost sends every registry request to the test server.
type rewriteHost string

func (r rewriteHost) RoundTrip(req *http.Request) (*http.Response, error) {
	u := string(r) + req.URL.Path
	newReq, _ := http.NewRequestWithContext(req.Context(), req.Method, u, req.Body)
	for k, v := range req.Header {
		newReq.Header[k] = v
	}
	return http.DefaultTransport.RoundTrip(newReq)
}

func mockRegistry(t *testing.T, published map[string]map[string]time.Time) *registry.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		times, ok := published[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		versions := map[string]any{}
		timeMap := map[string]string{}
		latest := ""
		for v, at := range times {
			versions[v] = map[string]any{}
			timeMap[v] = at.Format(time.RFC3339)
			latest = v
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": name, "versions": versions, "time": timeMap,
			"dist-tags": map[string]string{"latest": latest},
		})
	}))
	t.Cleanup(srv.Close)
	client := registry.NewClient(filepath.Join(t.TempDir(), "cache"))
	client.HTTP = &http.Client{Transport: rewriteHost(srv.URL)}
	return client
}

func TestCheckFlagsFreshTransitiveEntriesOfALockfileOnlyTarget(t *testing.T) {
	root := t.TempDir()
	lock := `{"lockfileVersion": 3, "packages": {
  "": {"name": "app"},
  "node_modules/top": {"version": "1.0.0"},
  "node_modules/top/node_modules/deep": {"version": "2.0.0"}
}}`
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	reg := mockRegistry(t, map[string]map[string]time.Time{
		"top":  {"1.0.0": now.Add(-90 * 24 * time.Hour)},
		"deep": {"2.0.0": now.Add(-2 * time.Hour)},
	})

	hits, err := Check(root, 7, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Name != "deep" || hits[0].Version != "2.0.0" {
		t.Fatalf("hits = %+v, want only the fresh transitive deep@2.0.0", hits)
	}
}

func TestCheckDeduplicatesInstalledAndLockedVersions(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"),
		[]byte(`{"packages": {"node_modules/top": {"version": "1.0.0"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(root, "node_modules", "top")
	if err := os.MkdirAll(installed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installed, "package.json"),
		[]byte(`{"name": "top", "version": "1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := mockRegistry(t, map[string]map[string]time.Time{
		"top": {"1.0.0": time.Now().Add(-time.Hour)},
	})
	hits, err := Check(root, 7, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("hits = %+v, want one deduplicated hit", hits)
	}
}
