// Package registry is a cached HTTP client for the npm public registry.
// It's used by the freshness check (issue #5) and maintainer-change detection
// (issue #6).
package registry

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// ErrNotFound is returned when the registry returns 404 for a name.
var ErrNotFound = errors.New("registry: package not found")

// Maintainer is one entry in the package's maintainers array.
type Maintainer struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// Packument is the relevant subset of npm's registry response.
// The full document is large; we only decode the fields we care about.
type Packument struct {
	Name        string               `json:"name"`
	Time        map[string]time.Time `json:"time"`
	Maintainers []Maintainer         `json:"maintainers"`
}

// Client is a cached registry HTTP client.
type Client struct {
	CacheDir string
	TTL      time.Duration
	HTTP     *http.Client
}

// NewClient returns a client with a 24h cache TTL and 8s request timeout.
func NewClient(cacheDir string) *Client {
	return &Client{
		CacheDir: cacheDir,
		TTL:      24 * time.Hour,
		HTTP:     &http.Client{Timeout: 8 * time.Second},
	}
}

// Get returns the Packument for the named package, reading from cache when
// fresh, otherwise hitting the registry.
func (c *Client) Get(name string) (*Packument, error) {
	cachePath := c.cachePath(name)
	if p, err := c.readCache(cachePath); err == nil {
		return p, nil
	}
	p, err := c.fetch(name)
	if err != nil {
		return nil, err
	}
	c.writeCache(cachePath, p)
	return p, nil
}

func (c *Client) cachePath(name string) string {
	h := sha1.Sum([]byte(name))
	return filepath.Join(c.CacheDir, "npm", hex.EncodeToString(h[:])+".json")
}

func (c *Client) readCache(path string) (*Packument, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if time.Since(st.ModTime()) > c.TTL {
		return nil, errors.New("expired")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Packument
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (c *Client) writeCache(path string, p *Packument) {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	b, err := json.Marshal(p)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, b, 0o644)
}

func (c *Client) fetch(name string) (*Packument, error) {
	// Scoped packages (@scope/name) must have the '/' percent-encoded as %2F
	// for some registry mirrors; the official registry accepts both but we
	// use the safe form.
	encoded := url.PathEscape(name)
	u := "https://registry.npmjs.org/" + encoded

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, ErrNotFound
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("registry %s: %s", name, resp.Status)
	}
	var p Packument
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, err
	}
	return &p, nil
}
