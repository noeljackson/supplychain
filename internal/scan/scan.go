// Package scan orchestrates a single-target scan, combining manifest, lockfile,
// IOC, and OSV checks.
package scan

import (
	"errors"
	"io/fs"

	"github.com/noeljackson/supplychain/internal/freshness"
	"github.com/noeljackson/supplychain/internal/ioc"
	"github.com/noeljackson/supplychain/internal/maintainer"
	"github.com/noeljackson/supplychain/internal/manifest"
	"github.com/noeljackson/supplychain/internal/npmsig"
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
		len(f.Maintainers) > 0
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
	persistList, err := ioc.LoadList(opts.OpenIOC, "persistence-paths.txt")
	if err != nil {
		return f, err
	}
	payloadList, err := ioc.LoadList(opts.OpenIOC, "payload-filenames.txt")
	if err != nil {
		return f, err
	}

	f.Manifest, err = manifest.ScanRepo(opts.Target, pkgs)
	if err != nil {
		return f, err
	}
	f.Lockfile, err = manifest.ScanLockfiles(opts.Target, pkgs)
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

	osvHits, osvErr := osv.Scan(opts.BinDir, opts.Target)
	if osvErr == nil {
		// osv.Scan returns nil findings when osv-scanner isn't installed.
		// If we got here without error, treat it as available iff we got data.
		if osvHits != nil {
			f.OSV = osvHits
		}
		f.OSVAvailable = osvHits != nil || isAvailable(opts.BinDir)
	}
	return f, nil
}

func isAvailable(binDir string) bool {
	_, _, err := osv.Locate(binDir)
	return err == nil
}
