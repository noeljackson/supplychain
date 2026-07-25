package maintainer

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/noeljackson/supplychain/internal/registry"
)

func TestDiffSets(t *testing.T) {
	cases := []struct {
		name        string
		prev, curr  []string
		wantAdded   []string
		wantRemoved []string
	}{
		{
			name:        "no change",
			prev:        []string{"a", "b"},
			curr:        []string{"a", "b"},
			wantAdded:   nil,
			wantRemoved: nil,
		},
		{
			name:        "added one",
			prev:        []string{"a"},
			curr:        []string{"a", "b"},
			wantAdded:   []string{"b"},
			wantRemoved: nil,
		},
		{
			name:        "removed one",
			prev:        []string{"a", "b"},
			curr:        []string{"a"},
			wantAdded:   nil,
			wantRemoved: []string{"b"},
		},
		{
			name:        "swap one",
			prev:        []string{"alice", "bob"},
			curr:        []string{"alice", "attacker"},
			wantAdded:   []string{"attacker"},
			wantRemoved: []string{"bob"},
		},
		{
			name:        "first time (prev empty)",
			prev:        nil,
			curr:        []string{"alice"},
			wantAdded:   []string{"alice"},
			wantRemoved: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, r := diffSets(c.prev, c.curr)
			if !reflect.DeepEqual(a, c.wantAdded) {
				t.Errorf("added: got %v, want %v", a, c.wantAdded)
			}
			if !reflect.DeepEqual(r, c.wantRemoved) {
				t.Errorf("removed: got %v, want %v", r, c.wantRemoved)
			}
		})
	}
}

func TestMaintainersToStrings_DedupSorts(t *testing.T) {
	in := []registry.Maintainer{
		{Name: "bob"},
		{Name: "alice"},
		{Name: "bob"}, // dup
		{Email: "carol@example.com"},
		{}, // empty, skipped
	}
	got := maintainersToStrings(in)
	want := []string{"alice", "bob", "carol@example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCheckRequiresExplicitBaselineAcceptance(t *testing.T) {
	current := "alice"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"maintainers":[{"name":"` + current + `"}]}`))
	}))
	defer server.Close()
	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &registry.Client{
		CacheDir: t.TempDir(),
		TTL:      -1,
		HTTP: &http.Client{
			Transport: maintainerRewriteHost{base: base, next: http.DefaultTransport},
		},
	}
	target := t.TempDir()
	if err := os.MkdirAll(filepath.Join(target, "node_modules", "fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	baselineDir := t.TempDir()

	for attempt := 0; attempt < 2; attempt++ {
		hits, err := Check(target, client, baselineDir, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) != 1 || hits[0].Reason != "baseline-missing" {
			t.Fatalf("attempt %d hits = %+v", attempt, hits)
		}
	}
	if hits, err := Check(target, client, baselineDir, true); err != nil || len(hits) != 0 {
		t.Fatalf("accept initial baseline: hits=%+v err=%v", hits, err)
	}
	if _, err := os.Stat(baselinePath(baselineDir, "fixture")); err != nil {
		t.Fatalf("accepted baseline missing: %v", err)
	}

	current = "mallory"
	for attempt := 0; attempt < 2; attempt++ {
		hits, err := Check(target, client, baselineDir, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) != 1 || hits[0].Reason != "maintainer-change" ||
			!reflect.DeepEqual(hits[0].Added, []string{"mallory"}) {
			t.Fatalf("attempt %d hits = %+v", attempt, hits)
		}
	}
	if hits, err := Check(target, client, baselineDir, true); err != nil || len(hits) != 0 {
		t.Fatalf("accept change: hits=%+v err=%v", hits, err)
	}
	hits, err := Check(target, client, baselineDir, false)
	if err != nil || len(hits) != 0 {
		t.Fatalf("accepted state should be clean: hits=%+v err=%v", hits, err)
	}
	entries, err := os.ReadDir(baselineDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("temporary baseline left behind: %s", entry.Name())
		}
	}
}

func TestCheckFileCreatesDeterministicTrackedBaseline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"maintainers":[{"name":"alice"}]}`))
	}))
	defer server.Close()
	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &registry.Client{
		CacheDir: t.TempDir(),
		TTL:      -1,
		HTTP: &http.Client{
			Transport: maintainerRewriteHost{base: base, next: http.DefaultTransport},
		},
	}
	target := t.TempDir()
	if err := exec.Command("git", "-C", target, "init", "-q").Run(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(target, "node_modules", "fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	const relative = ".supplychain/maintainers.json"
	for attempt := 0; attempt < 2; attempt++ {
		hits, err := CheckFile(target, client, relative, false)
		if err != nil || len(hits) != 1 || hits[0].Reason != "baseline-missing" {
			t.Fatalf("attempt %d: hits=%+v err=%v", attempt, hits, err)
		}
	}
	if hits, err := CheckFile(target, client, relative, true); err != nil || len(hits) != 0 {
		t.Fatalf("accept file baseline: hits=%+v err=%v", hits, err)
	}
	path := filepath.Join(target, relative)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "updated_at") {
		t.Fatalf("baseline is nondeterministic: %s", body)
	}
	if err := exec.Command("git", "-C", target, "add", relative).Run(); err != nil {
		t.Fatal(err)
	}
	if hits, err := CheckFile(target, client, relative, false); err != nil || len(hits) != 0 {
		t.Fatalf("tracked accepted baseline: hits=%+v err=%v", hits, err)
	}
}

type maintainerRewriteHost struct {
	base *url.URL
	next http.RoundTripper
}

func (r maintainerRewriteHost) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = r.base.Scheme
	clone.URL.Host = r.base.Host
	return r.next.RoundTrip(clone)
}
