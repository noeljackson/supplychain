package osm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestTokenFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "osm-token")
	if err := os.WriteFile(path, []byte("test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := TokenFromFile(path)
	if err != nil {
		t.Fatalf("TokenFromFile() error = %v", err)
	}
	if token != "test-token" {
		t.Fatalf("TokenFromFile() returned an unexpected token")
	}
}

func TestTokenFromFileRejectsUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	secure := filepath.Join(dir, "secure")
	if err := os.WriteFile(secure, []byte("test-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	broader := filepath.Join(dir, "broader")
	if err := os.WriteFile(broader, []byte("test-token"), 0o640); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "symlink")
	if err := os.Symlink(secure, symlink); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(dir, "directory")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{broader, symlink, directory} {
		if _, err := TokenFromFile(path); err == nil {
			t.Errorf("TokenFromFile(%q) unexpectedly succeeded", filepath.Base(path))
		}
	}
}

func TestParseVersionInfo_ConcretePins(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"1.2.3", []string{"1.2.3"}},
		{"1.2.3-beta.1", []string{"1.2.3-beta.1"}},
		{"1.2.3, 1.2.4", []string{"1.2.3", "1.2.4"}},
		{"1.2.3,1.2.4", []string{"1.2.3", "1.2.4"}},
		{"  1.2.3 ;  1.2.4  ", []string{"1.2.3", "1.2.4"}},
		{"1.2.3 1.2.3 1.2.4", []string{"1.2.3", "1.2.4"}}, // dedup
	}
	for _, c := range cases {
		got := parseVersionInfo(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseVersionInfo(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseVersionInfo_RangesRejected(t *testing.T) {
	rejects := []string{
		"^1.2.3",
		"~1.2.3",
		">=1.0.0, <2.0.0",
		">1.0",
		"*",
		"",
		"1.x",
		"latest",
		"1.2",     // not full semver
		"1.2.3.4", // not semver
	}
	for _, in := range rejects {
		if got := parseVersionInfo(in); got != nil {
			t.Errorf("parseVersionInfo(%q) = %v, want nil (range or invalid)", in, got)
		}
	}
}

func TestQueryLatestRetriesTransientServerFailure(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/query-latest" || r.URL.Query().Get("ecosystem") != "npm" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		if attempts.Add(1) == 1 {
			http.Error(w, "temporary gateway failure", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ecosystem":"npm","count":1,"threats":[{"id":"1","package_name":"bad","version_info":"1.2.3"}]}`))
	}))
	defer server.Close()

	threats, err := queryLatestAt(context.Background(), server.Client(), "test-token", "npm", server.URL)
	if err != nil {
		t.Fatalf("queryLatestAt() error = %v", err)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
	if len(threats) != 1 || threats[0].PackageName != "bad" {
		t.Fatalf("threats = %#v", threats)
	}
}

func TestQueryLatestDoesNotRetryAuthenticationFailure(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	_, err := queryLatestAt(context.Background(), server.Client(), "test-token", "npm", server.URL)
	if err == nil {
		t.Fatal("queryLatestAt() unexpectedly succeeded")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts = %d, want 1", got)
	}
}

func TestQueryLatestStopsWhenContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts atomic.Int32
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		attempts.Add(1)
		cancel()
		return nil, errors.New("temporary network failure")
	})}

	_, err := queryLatestAt(ctx, client, "test-token", "npm", "https://example.invalid")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("queryLatestAt() error = %v, want context cancellation", err)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts = %d, want 1", got)
	}
}
