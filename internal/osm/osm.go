// Package osm integrates the free-tier OpenSourceMalware.com query-latest
// endpoint as a supplemental IOC source. OSM has demonstrated lead time over
// OSV/GHSA on recent npm campaigns (Mini Shai-Hulud, TeamPCP/Mistral, etc.).
// The free-tier TOS permits ingestion into internal security tools.
//
// Activation: set SUPPLYCHAIN_OSM_TOKEN. Absent → integration is a no-op.
// Cache lives at $DataDir/osm-cache.json with full provenance per entry.
package osm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/noeljackson/supplychain/internal/ioc"
)

const (
	BaseURL    = "https://api.opensourcemalware.com/functions/v1"
	envToken   = "SUPPLYCHAIN_OSM_TOKEN"
	UserAgent  = "supplychain/dev (+https://github.com/noeljackson/supplychain)"
	httpTimeout = 15 * time.Second
)

// Token returns the bearer token from the environment, "" if unset.
func Token() string { return os.Getenv(envToken) }

// Threat is the relevant subset of one entry in the query-latest response.
type Threat struct {
	ID          string `json:"id"`
	PackageName string `json:"package_name"`
	Description string `json:"threat_description"`
	Severity    string `json:"severity_level"`
	Registry    string `json:"registry"`
	Publisher   string `json:"publisher"`
	VersionInfo string `json:"version_info"`
	CreatedAt   string `json:"created_at"`
	Tags        []string `json:"tags"`
}

// QueryLatestResponse is the shape returned by GET /query-latest?ecosystem=...
type QueryLatestResponse struct {
	Ecosystem string   `json:"ecosystem"`
	Count     int      `json:"count"`
	Threats   []Threat `json:"threats"`
}

// CachedEntry is one IOC sourced from OSM that we've decided to apply during
// scans. The Package + Version pair is what gets matched.
type CachedEntry struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	ThreatID    string `json:"threat_id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Tags        []string `json:"tags,omitempty"`
}

// SkippedEntry is an OSM threat we couldn't reduce to a concrete (name, version)
// pair because version_info was a range or otherwise non-pin-shaped. We record
// it for human visibility but it doesn't participate in matching.
type SkippedEntry struct {
	ThreatID    string `json:"threat_id"`
	Name        string `json:"name"`
	VersionInfo string `json:"version_info"`
	Reason      string `json:"reason"`
}

// Cache is the on-disk OSM artifact. Versioned via FetchedAt + Ecosystems so a
// future fetch can compare without re-parsing.
type Cache struct {
	FetchedAt  time.Time      `json:"fetched_at"`
	Ecosystems []string       `json:"ecosystems"`
	Entries    []CachedEntry  `json:"entries"`
	Skipped    []SkippedEntry `json:"skipped"`
}

// CachePath is the canonical on-disk location relative to a data dir.
func CachePath(dataDir string) string {
	return dataDir + "/osm-cache.json"
}

// LoadCache reads the cache file if it exists. Returns (nil, nil) — not an
// error — when the file is absent.
func LoadCache(path string) (*Cache, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var c Cache
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// LoadCacheAsPackageIOCs reads the cache and translates each entry into the
// same ioc.PackageIOC shape the matcher already consumes. Returns nil when no
// cache exists.
func LoadCacheAsPackageIOCs(path string) ([]ioc.PackageIOC, error) {
	c, err := LoadCache(path)
	if err != nil || c == nil {
		return nil, err
	}
	out := make([]ioc.PackageIOC, 0, len(c.Entries))
	for _, e := range c.Entries {
		p := ioc.PackageIOC{Name: e.Name, Version: e.Version}
		if v, err := semver.NewVersion(e.Version); err == nil {
			p.Parsed = v
		}
		out = append(out, p)
	}
	return out, nil
}

// Refresh fetches /query-latest for each ecosystem and rewrites the cache.
// Returns (skipped: true, nil) when no token is configured — the caller should
// treat this as a normal no-op, not an error. Returns the count of entries
// added/skipped on success.
func Refresh(ctx context.Context, dataDir string, ecosystems []string) (skipped bool, added int, ignored int, err error) {
	tok := Token()
	if tok == "" {
		return true, 0, 0, nil
	}
	if len(ecosystems) == 0 {
		ecosystems = []string{"npm"}
	}

	client := &http.Client{Timeout: httpTimeout}
	cache := &Cache{
		FetchedAt:  time.Now().UTC(),
		Ecosystems: ecosystems,
	}

	for _, eco := range ecosystems {
		threats, err := queryLatest(ctx, client, tok, eco)
		if err != nil {
			return false, 0, 0, fmt.Errorf("query-latest(%s): %w", eco, err)
		}
		for _, t := range threats {
			versions := parseVersionInfo(t.VersionInfo)
			if len(versions) == 0 {
				cache.Skipped = append(cache.Skipped, SkippedEntry{
					ThreatID: t.ID, Name: t.PackageName,
					VersionInfo: t.VersionInfo, Reason: "no-concrete-version",
				})
				continue
			}
			for _, v := range versions {
				cache.Entries = append(cache.Entries, CachedEntry{
					Name: t.PackageName, Version: v,
					ThreatID: t.ID, Severity: t.Severity,
					Description: t.Description, Tags: t.Tags,
				})
			}
		}
	}

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return false, 0, 0, err
	}
	b, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return false, 0, 0, err
	}
	if err := os.WriteFile(CachePath(dataDir), b, 0o644); err != nil {
		return false, 0, 0, err
	}
	return false, len(cache.Entries), len(cache.Skipped), nil
}

func queryLatest(ctx context.Context, client *http.Client, token, eco string) ([]Threat, error) {
	url := BaseURL + "/query-latest?ecosystem=" + eco
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	switch resp.StatusCode {
	case 200:
	case 401:
		return nil, fmt.Errorf("auth failed (401) — check SUPPLYCHAIN_OSM_TOKEN")
	case 403:
		return nil, fmt.Errorf("forbidden (403) — endpoint may require Pro tier")
	case 429:
		return nil, fmt.Errorf("rate limited (429); retry later")
	default:
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, snippet(body))
	}

	var doc QueryLatestResponse
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return doc.Threats, nil
}

// parseVersionInfo extracts concrete semver pins from OSM's version_info field.
// Acceptable shapes: "1.2.3", "1.2.3, 1.2.4", "1.2.3,1.2.4" (commas optional).
// Range-style ("^1", ">=1, <2", "*") returns empty so the caller can route it
// to Skipped — we don't want to over-flag from a range we can't faithfully
// match against the matchers we have.
func parseVersionInfo(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return nil
	}
	// Reject obvious range markers before tokenising.
	if strings.ContainsAny(s, "^~><=*") {
		return nil
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' })
	var out []string
	seen := make(map[string]struct{})
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !semverPin.MatchString(p) {
			return nil
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

var semverPin = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[0-9A-Za-z\-.]+)?(?:\+[0-9A-Za-z\-.]+)?$`)

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
