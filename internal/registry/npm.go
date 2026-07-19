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

// Signature is an npm registry ECDSA signature over
// `${package.name}@${package.version}:${package.dist.integrity}`.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// Attestations advertises the registry endpoint containing Sigstore bundles.
type Attestations struct {
	URL        string `json:"url"`
	Provenance *struct {
		PredicateType string `json:"predicateType"`
	} `json:"provenance,omitempty"`
}

// Dist is the integrity and signing metadata for one published version.
type Dist struct {
	Integrity    string        `json:"integrity"`
	Tarball      string        `json:"tarball"`
	Signatures   []Signature   `json:"signatures"`
	Attestations *Attestations `json:"attestations,omitempty"`
}

// VersionMetadata is the subset of version metadata needed by verification.
type VersionMetadata struct {
	Dist Dist `json:"dist"`
}

// SigningKey is one public npm registry signing key.
type SigningKey struct {
	Expires string `json:"expires"`
	KeyID   string `json:"keyid"`
	KeyType string `json:"keytype"`
	Scheme  string `json:"scheme"`
	Key     string `json:"key"`
}

// Packument is the relevant subset of npm's registry response.
// The full document is large; we only decode the fields we care about.
type Packument struct {
	Name        string               `json:"name"`
	Time        map[string]time.Time `json:"time"`
	Maintainers []Maintainer         `json:"maintainers"`
	DistTags    map[string]string    `json:"dist-tags"`
	// Versions holds entries for currently-published versions only. We don't
	// decode the per-version metadata — just the set of keys — so a small
	// stub is enough. Unpublished versions still appear in Time but not here.
	Versions map[string]VersionMetadata `json:"versions"`
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
		HTTP:     &http.Client{Timeout: 15 * time.Second},
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

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	req.Header.Set("Accept", "application/json")

	resp, err := c.doWithRetry(req)
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

// SigningKeys fetches the npm registry's public ECDSA signing keys. Keys are
// deliberately not persisted in the package metadata cache because rotations
// must be observed promptly by signature verification.
func (c *Client) SigningKeys() ([]SigningKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://registry.npmjs.org/-/npm/v1/keys", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := c.doWithRetry(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry signing keys: %s", resp.Status)
	}
	var doc struct {
		Keys []SigningKey `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	return doc.Keys, nil
}

func (c *Client) doWithRetry(req *http.Request) (*http.Response, error) {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		clone := req.Clone(req.Context())
		resp, err := c.HTTP.Do(clone)
		if err == nil {
			return resp, nil
		}
		last = err
		if req.Context().Err() != nil {
			break
		}
		time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
	}
	return nil, last
}
