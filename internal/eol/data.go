// Package eol finds the language runtimes, package managers, toolchains and
// container base images a repository pins, and judges each pin against
// end-of-life data: a release cycle past its end of life is a finding, and a
// pin that is about to reach it, has left active support or trails its cycle's
// newest release is a warning.
//
// The data is endoflife.date's v1 product document
// (https://endoflife.date/api/v1/products/<product>/), one file per product in
// <data dir>/eol/<product>.json. `supplychain update` and `supplychain ci
// --refresh-eol` fetch it; offline CI receives it in an advisory bundle.
package eol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Products are the endoflife.date products the scanner judges pins against.
// Node.js also covers Actions `runs.using: nodeNN` runtimes.
var Products = []string{
	"alpine-linux",
	"bun",
	"debian",
	"go",
	"nodejs",
	"python",
	"rust",
	"ubuntu",
}

const (
	// DefaultBaseURL serves one v1 product document per product name.
	DefaultBaseURL = "https://endoflife.date/api/v1/products"
	// EnvBaseURL overrides DefaultBaseURL, e.g. for a mirror.
	EnvBaseURL   = "SUPPLYCHAIN_EOL_URL"
	maxDocument  = 4 << 20
	fetchTimeout = 20 * time.Second
)

// Dir is where the per-product documents live under a data directory.
func Dir(dataDir string) string { return filepath.Join(dataDir, "eol") }

// Version is one release of a cycle.
type Version struct {
	Name string  `json:"name"`
	Date *string `json:"date"`
}

// Release is one release cycle, e.g. Node.js "22" or Debian "12".
type Release struct {
	Name        string   `json:"name"`
	Codename    *string  `json:"codename"`
	ReleaseDate string   `json:"releaseDate"`
	IsEOL       bool     `json:"isEol"`
	EOLFrom     *string  `json:"eolFrom"`
	IsEOAS      *bool    `json:"isEoas,omitempty"`
	EOASFrom    *string  `json:"eoasFrom,omitempty"`
	Latest      *Version `json:"latest"`
}

// Product is the part of an endoflife.date v1 product document the scanner uses.
type Product struct {
	Name     string    `json:"name"`
	Label    string    `json:"label"`
	Releases []Release `json:"releases"`
}

type document struct {
	SchemaVersion string  `json:"schema_version"`
	GeneratedAt   string  `json:"generated_at"`
	LastModified  string  `json:"last_modified"`
	Result        Product `json:"result"`
}

// Catalog maps a product name to its data.
type Catalog map[string]Product

// Parse validates one product document. It accepts only schema 1.x, the named
// product, at least one release, and well-formed dates, so a truncated or
// substituted document cannot silently pass every pin.
func Parse(product string, raw []byte) (Product, error) {
	var doc document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Product{}, fmt.Errorf("end-of-life data for %s is not JSON: %w", product, err)
	}
	if !strings.HasPrefix(doc.SchemaVersion, "1.") {
		return Product{}, fmt.Errorf("end-of-life data for %s has unsupported schema_version %q", product, doc.SchemaVersion)
	}
	if doc.Result.Name != product {
		return Product{}, fmt.Errorf("end-of-life data for %s names product %q", product, doc.Result.Name)
	}
	if len(doc.Result.Releases) == 0 {
		return Product{}, fmt.Errorf("end-of-life data for %s lists no releases", product)
	}
	for _, release := range doc.Result.Releases {
		if release.Name == "" {
			return Product{}, fmt.Errorf("end-of-life data for %s has a release without a name", product)
		}
		for _, date := range []*string{release.EOLFrom, release.EOASFrom} {
			if date != nil {
				if _, err := time.Parse(time.DateOnly, *date); err != nil {
					return Product{}, fmt.Errorf("end-of-life data for %s release %s has a malformed date %q", product, release.Name, *date)
				}
			}
		}
	}
	return doc.Result, nil
}

// Load reads the named products from dir. A product whose file is absent is
// returned in missing; a present but invalid file is an error.
func Load(dir string, products []string) (Catalog, []string, error) {
	catalog := make(Catalog, len(products))
	var missing []string
	for _, product := range products {
		raw, err := readBounded(filepath.Join(dir, product+".json"))
		if errors.Is(err, os.ErrNotExist) {
			missing = append(missing, product)
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read end-of-life data for %s: %w", product, err)
		}
		parsed, err := Parse(product, raw)
		if err != nil {
			return nil, nil, err
		}
		catalog[product] = parsed
	}
	return catalog, missing, nil
}

func readBounded(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxDocument+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxDocument {
		return nil, fmt.Errorf("%s exceeds %d bytes", filepath.Base(path), maxDocument)
	}
	return raw, nil
}

// BaseURL returns the configured product document origin.
func BaseURL() string {
	if value := os.Getenv(EnvBaseURL); value != "" {
		return strings.TrimRight(value, "/")
	}
	return DefaultBaseURL
}

// Refresh downloads every product document from baseURL, validates each one,
// and only then replaces the files in dir, so a partial download never leaves
// a mixed set behind.
func Refresh(ctx context.Context, client *http.Client, baseURL, dir string) error {
	if client == nil {
		client = &http.Client{Timeout: fetchTimeout}
	}
	fetched := make(map[string][]byte, len(Products))
	for _, product := range Products {
		raw, err := fetch(ctx, client, baseURL+"/"+product+"/")
		if err != nil {
			return fmt.Errorf("fetch end-of-life data for %s: %w", product, err)
		}
		if _, err := Parse(product, raw); err != nil {
			return err
		}
		fetched[product] = raw
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, product := range Products {
		final := filepath.Join(dir, product+".json")
		temporary := final + ".tmp"
		if err := os.WriteFile(temporary, fetched[product], 0o644); err != nil {
			return err
		}
		if err := os.Rename(temporary, final); err != nil {
			_ = os.Remove(temporary)
			return err
		}
	}
	return nil
}

func fetch(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxDocument+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxDocument {
		return nil, fmt.Errorf("response exceeds %d bytes", maxDocument)
	}
	return bytes.TrimSpace(raw), nil
}
