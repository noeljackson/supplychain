package registry

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type failingReadCloser struct {
	err error
}

func (r *failingReadCloser) Read([]byte) (int, error) {
	return 0, r.err
}

func (r *failingReadCloser) Close() error {
	return nil
}

func TestFetchRetriesBodyReadFailure(t *testing.T) {
	client := NewClient(t.TempDir())
	attempts := 0
	client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		attempts++
		body := io.ReadCloser(&failingReadCloser{err: context.DeadlineExceeded})
		if attempts == 2 {
			body = io.NopCloser(strings.NewReader(`{"name":"playwright-core","versions":{}}`))
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       body,
			Header:     make(http.Header),
		}, nil
	})

	packument, err := client.fetch("playwright-core")
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
	if packument.Name != "playwright-core" {
		t.Fatalf("name = %q", packument.Name)
	}
}

func TestFetchJSONRejectsOversizedBody(t *testing.T) {
	client := NewClient(t.TempDir())
	client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader(`{"too":"large"}`)),
			Header:     make(http.Header),
		}, nil
	})
	req, err := http.NewRequest(http.MethodGet, "https://registry.npmjs.org/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = fetchJSONWithRetry[Packument](client, req, 4)
	if err == nil || !strings.Contains(err.Error(), "exceeds 4 bytes") {
		t.Fatalf("error = %v", err)
	}
}

func TestFetchJSONStopsWhenParentContextIsCancelled(t *testing.T) {
	client := NewClient(t.TempDir())
	attempts := 0
	client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		attempts++
		return nil, request.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://registry.npmjs.org/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = fetchJSONWithRetry[Packument](client, req, 1024)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}
