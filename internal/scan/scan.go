// Package scan orchestrates a single-target scan, combining manifest, lockfile,
// IOC, and OSV checks.
package scan

import (
	"errors"
	"io/fs"

	"github.com/noeljackson/supplychain/internal/drift"
	"github.com/noeljackson/supplychain/internal/freshness"
	"github.com/noeljackson/supplychain/internal/ioc"
	"github.com/noeljackson/supplychain/internal/maintainer"
	"github.com/noeljackson/supplychain/internal/manifest"
	"github.com/noeljackson/supplychain/internal/npmsig"
	"github.com/noeljackson/supplychain/internal/osm"
	"github.com/noeljackson/supplychain/internal/osv"
	"github.com/noeljackson/supplychain/internal/registry"
	"github.com/noeljackson/supplychain/internal/scripts"
	"github.com/noeljackson/supplychain/internal/typosquat"
)

// Options configures a scan.
type Options struct {
	Target  string
	BinDir  string
	OpenIOC func(name string) (fs.File, error)

	// FreshnessDays > 0 enables the registry-backed freshness check; 0 disables.
	FreshnessDays int

	// Registry is the npm registry client used by freshness (and future
	// registry-driven checks like maintainer-change). When nil, those checks
	// are silently skipped.
	Registry *registry.Client

	// Signatures enables `npm audit signatures` shell-out. No-op if npm
	// isn't on PATH or target has no package-lock.json.
	Signatures bool

	// Maintainers enables the maintainer-change check. Requires Registry +
	// MaintainerBaseDir. First scan establishes a silent baseline.
	Maintainers bool

	// MaintainerBaseDir is where per-package maintainer baselines live
	// (typically $DataDir/maintainers).
	MaintainerBaseDir string

	// TyposquatDistance overrides typosquat.DefaultMaxDistance when > 0.
	TyposquatDistance int

	// OSMCachePath is the path to the OSM IOC cache (osm-cache.json).
	// When non-empty and the file exists, its package IOCs are unioned
	// into the matcher set.
	OSMCachePath string
}

// Findings is the aggregated result of a scan.
type Findings struct {
	Target string `json:"target"`

	Manifest    []manifest.ManifestHit `json:"manifest_hits"`
	Lockfile    []manifest.LockHit     `json:"lockfile_hits"`
	OSV         []osv.PackageVuln      `json:"osv_hits"`
	Payloads    []ioc.PayloadHit       `json:"payload_hits"`
	Persistence []string               `json:"persistence_hits"`
	Scripts     []scripts.Hit          `json:"script_hits"`
	Freshness   []freshness.Hit        `json:"freshness_hits"`
	Typosquat   []typosquat.Hit        `json:"typosquat_hits"`
	Signatures  []npmsig.Hit           `json:"signature_hits"`
	Maintainers []maintainer.Hit       `json:"maintainer_changes"`
	Drift       []drift.Hit            `json:"drift_hits"`

	OSVAvailable bool `json:"osv_available"`
}

// HasHits returns true for anything that should be treated as a finding —
// notably NOT Scripts or Freshness (informational only). Maintainer changes
// DO count: a mid-stream maintainer-set change is the canonical leading
// indicator of an account-takeover supply-chain attack.
func (f Findings) HasHits() bool {
	return len(f.Manifest) > 0 ||
		len(f.Lockfile) > 0 ||
		len(f.OSV) > 0 ||
		len(f.Payloads) > 0 ||
		len(f.Persistence) > 0 ||
		len(f.Typosquat) > 0 ||
		len(f.Signatures) > 0 ||
		len(f.Maintainers) > 0 ||
		len(f.Drift) > 0
}

// Run executes the scan.
func Run(opts Options) (Findings, error) {
	f := Findings{Target: opts.Target}
	if opts.OpenIOC == nil {
		return f, errors.New("scan: OpenIOC is required")
	}

	pkgs, err := ioc.LoadPackages(opts.OpenIOC)
	if err != nil {
		return f, err
	}
	if opts.OSMCachePath != "" {
		if extra, err := osm.LoadCacheAsPackageIOCs(opts.OSMCachePath); err == nil && len(extra) > 0 {
			pkgs = append(pkgs, extra...)
		}
	}
	persistList, err := ioc.LoadList(opts.OpenIOC, "persistence-paths.txt")
	if err != nil {
		return f, err
	}
	payloadList, err := ioc.LoadList(opts.OpenIOC, "payload-filenames.txt")
	if err != nil {
		return f, err
	}
	blockedNames, err := ioc.LoadList(opts.OpenIOC, "blocked-package-names.txt")
	if err != nil {
		// File may not exist on older overrides — treat as empty.
		blockedNames = nil
	}

	f.Manifest, err = manifest.ScanRepo(opts.Target, pkgs, blockedNames, opts.Registry)
	if err != nil {
		return f, err
	}
	f.Lockfile, err = manifest.ScanLockfiles(opts.Target, pkgs, blockedNames)
	if err != nil {
		return f, err
	}
	f.Payloads, err = ioc.FindPayloads(opts.Target, payloadList)
	if err != nil {
		return f, err
	}
	f.Persistence = ioc.CheckPersistence(persistList)

	f.Scripts, err = scripts.ScanInstalled(opts.Target)
	if err != nil {
		return f, err
	}

	f.Drift, err = drift.ScanRepo(opts.Target)
	if err != nil {
		return f, err
	}

	if opts.FreshnessDays > 0 && opts.Registry != nil {
		f.Freshness, err = freshness.Check(opts.Target, opts.FreshnessDays, opts.Registry)
		if err != nil {
			return f, err
		}
	}

	if opts.TyposquatDistance > 0 {
		f.Typosquat, err = typosquat.CheckWith(opts.Target, opts.TyposquatDistance)
	} else {
		f.Typosquat, err = typosquat.Check(opts.Target)
	}
	if err != nil {
		return f, err
	}

	if opts.Signatures {
		f.Signatures, err = npmsig.Run(opts.Target)
		if err != nil {
			return f, err
		}
	}

	if opts.Maintainers && opts.Registry != nil && opts.MaintainerBaseDir != "" {
		f.Maintainers, err = maintainer.Check(opts.Target, opts.Registry, opts.MaintainerBaseDir)
		if err != nil {
			return f, err
		}
	}

	// Availability is independent of whether the scan returned findings —
	// a clean OSV scan also returns no hits but is "available".
	f.OSVAvailable = isAvailable(opts.BinDir)
	if f.OSVAvailable {
		osvHits, osvErr := osv.Scan(opts.BinDir, opts.Target)
		if osvErr == nil && osvHits != nil {
			f.OSV = osvHits
		}
	}
	return f, nil
}

func isAvailable(binDir string) bool {
	_, _, err := osv.Locate(binDir)
	return err == nil
}
