// Package scan orchestrates a single-target scan, combining manifest, lockfile,
// IOC, and OSV checks.
package scan

import (
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"time"

	"github.com/noeljackson/supplychain/internal/check"
	"github.com/noeljackson/supplychain/internal/drift"
	"github.com/noeljackson/supplychain/internal/freshness"
	"github.com/noeljackson/supplychain/internal/ioc"
	"github.com/noeljackson/supplychain/internal/maintainer"
	"github.com/noeljackson/supplychain/internal/manifest"
	"github.com/noeljackson/supplychain/internal/npmsig"
	"github.com/noeljackson/supplychain/internal/osm"
	"github.com/noeljackson/supplychain/internal/osv"
	"github.com/noeljackson/supplychain/internal/policy"
	"github.com/noeljackson/supplychain/internal/registry"
	"github.com/noeljackson/supplychain/internal/scripts"
	"github.com/noeljackson/supplychain/internal/typosquat"
	"github.com/noeljackson/supplychain/internal/vendorartifact"
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
	// MaintainerBaseDir.
	Maintainers bool

	// AcceptMaintainers explicitly writes current maintainer sets after review.
	AcceptMaintainers bool

	// MaintainerBaseDir is where per-package maintainer baselines live
	// (typically $DataDir/maintainers).
	MaintainerBaseDir string

	// MaintainerBaseline selects a deterministic tracked baseline file within
	// Target. It takes precedence over MaintainerBaseDir.
	MaintainerBaseline string

	// TyposquatDistance overrides typosquat.DefaultMaxDistance when > 0.
	TyposquatDistance int

	// OSMCachePath is the path to the OSM IOC cache (osm-cache.json).
	// When non-empty and the file exists, its package IOCs are unioned
	// into the matcher set.
	OSMCachePath string

	// RequireOSV makes an unavailable or failed OSV scan fatal. Strict CI sets
	// this so advisory coverage can never disappear silently.
	RequireOSV bool

	// RequireComplete makes incomplete or failed required checks a policy
	// failure. CI strict policy and --fail-on-advisory enable it.
	RequireComplete bool

	// SourcePolicy selects a tracked policy within Target. Empty uses
	// .supplychain/source-policy.json when present, otherwise the built-in
	// all-advisories policy.
	SourcePolicy string
}

// Findings is the aggregated result of a scan.
type Findings struct {
	Target string `json:"target"`

	Manifest    []manifest.ManifestHit `json:"manifest_hits"`
	Lockfile    []manifest.LockHit     `json:"lockfile_hits"`
	OSV         []osv.PackageVuln      `json:"osv_hits"`
	Payloads    []ioc.PayloadHit       `json:"payload_hits"`
	Scripts     []scripts.Hit          `json:"script_hits"`
	Freshness   []freshness.Hit        `json:"freshness_hits"`
	Typosquat   []typosquat.Hit        `json:"typosquat_hits"`
	Signatures  []npmsig.Hit           `json:"signature_hits"`
	Vendored    []vendorartifact.Issue `json:"vendored_npm_hits"`
	Maintainers []maintainer.Hit       `json:"maintainer_changes"`
	Drift       []drift.Hit            `json:"drift_hits"`
	Suppressed  []policy.Suppressed    `json:"suppressed_findings"`
	Coverage    check.Coverage         `json:"coverage"`
	Policy      policy.Identity        `json:"policy"`
	Helpers     map[string]string      `json:"helpers"`
	DurationMS  int64                  `json:"duration_ms"`

	OSVAvailable bool      `json:"osv_available"`
	OSVStatus    OSVStatus `json:"osv_status"`
}

// OSVStatus distinguishes a completed scan from missing coverage and a target
// where dependency-vulnerability scanning is not applicable.
type OSVStatus string

const (
	OSVUnavailable   OSVStatus = "unavailable"
	OSVCompleted     OSVStatus = "completed"
	OSVNotApplicable OSVStatus = "not_applicable"
)

// HasSupplyChainHits returns true for indicators that point at dependency
// compromise, tampering, typosquatting, or maintainer takeover.
// It deliberately excludes OSV vulnerability advisories and manifest/lockfile
// drift: those are important audit signals, but they are not compromise IOCs.
func (f Findings) HasSupplyChainHits() bool {
	return len(f.Manifest) > 0 ||
		len(f.Lockfile) > 0 ||
		len(f.Payloads) > 0 ||
		len(f.Typosquat) > 0 ||
		len(f.Signatures) > 0 ||
		len(f.Vendored) > 0 ||
		len(f.Maintainers) > 0
}

// HasAdvisoryHits returns true for non-IOC dependency/audit findings.
func (f Findings) HasAdvisoryHits() bool {
	return len(f.OSV) > 0 ||
		len(f.Drift) > 0
}

// HasHits returns true for anything non-informational. Scripts and freshness
// remain informational only.
func (f Findings) HasHits() bool {
	return f.HasSupplyChainHits() || f.HasAdvisoryHits()
}

// HasCoverageGaps reports enabled checks that did not complete.
func (f Findings) HasCoverageGaps() bool {
	return f.Coverage.HasGaps()
}

// HasRequiredCoverageGaps reports incomplete required checks.
func (f Findings) HasRequiredCoverageGaps() bool {
	return f.Coverage.HasRequiredGaps()
}

// Run executes the scan.
func Run(opts Options) (f Findings, err error) {
	scanStarted := time.Now()
	f = Findings{
		Target:    opts.Target,
		OSVStatus: OSVUnavailable,
		Coverage:  make(check.Coverage),
		Helpers:   make(map[string]string),
	}
	defer func() {
		f.DurationMS = elapsedMS(scanStarted)
		SortFindings(&f)
	}()
	if opts.OpenIOC == nil {
		return f, errors.New("scan: OpenIOC is required")
	}
	checkStarted := time.Now()
	sourcePolicy, err := policy.Load(opts.Target, opts.SourcePolicy, time.Now())
	if err != nil {
		return f, fmt.Errorf("scan: %w", err)
	}
	f.Policy = sourcePolicy.Identity
	f.Coverage.Set("source_policy", check.StatusCompleted, opts.RequireComplete, "")
	f.Coverage.SetDuration("source_policy", elapsedMS(checkStarted))

	checkStarted = time.Now()
	pkgs, err := ioc.LoadPackages(opts.OpenIOC)
	if err != nil {
		return f, err
	}
	if opts.OSMCachePath != "" {
		extra, cacheErr := osm.LoadCacheAsPackageIOCs(opts.OSMCachePath)
		switch {
		case errors.Is(cacheErr, fs.ErrNotExist):
			f.Coverage.Set("osm_ioc_cache", check.StatusNotApplicable, false, "")
		case cacheErr != nil:
			f.Coverage.Set("osm_ioc_cache", check.StatusIncomplete, false, cacheErr.Error())
		case len(extra) == 0:
			f.Coverage.Set("osm_ioc_cache", check.StatusCompleted, false, "")
		default:
			pkgs = append(pkgs, extra...)
			f.Coverage.Set("osm_ioc_cache", check.StatusCompleted, false, "")
		}
	} else {
		f.Coverage.Set("osm_ioc_cache", check.StatusDisabled, false, "")
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
	f.Coverage.Set("ioc_data", check.StatusCompleted, opts.RequireComplete, "")
	f.Coverage.SetDuration("ioc_data", elapsedMS(checkStarted))

	checkStarted = time.Now()
	f.Manifest, err = manifest.ScanRepo(opts.Target, pkgs, blockedNames, opts.Registry)
	if err != nil {
		f.Coverage.Set("manifest_ioc", check.StatusFailed, opts.RequireComplete, err.Error())
	} else {
		f.Coverage.Set("manifest_ioc", check.StatusCompleted, opts.RequireComplete, "")
	}
	f.Coverage.SetDuration("manifest_ioc", elapsedMS(checkStarted))
	checkStarted = time.Now()
	f.Lockfile, err = manifest.ScanLockfiles(opts.Target, pkgs, blockedNames)
	if err != nil {
		f.Coverage.Set("lockfile_ioc", check.StatusFailed, opts.RequireComplete, err.Error())
	} else {
		f.Coverage.Set("lockfile_ioc", check.StatusCompleted, opts.RequireComplete, "")
	}
	f.Coverage.SetDuration("lockfile_ioc", elapsedMS(checkStarted))
	checkStarted = time.Now()
	f.Payloads, err = ioc.FindPayloads(opts.Target, payloadList)
	if err != nil {
		f.Coverage.Set("payload_ioc", check.StatusFailed, opts.RequireComplete, err.Error())
	} else {
		f.Coverage.Set("payload_ioc", check.StatusCompleted, opts.RequireComplete, "")
	}
	f.Coverage.SetDuration("payload_ioc", elapsedMS(checkStarted))

	checkStarted = time.Now()
	vendored, vendorErr := vendorartifact.Verify(opts.Target, opts.Registry)
	switch {
	case errors.Is(vendorErr, vendorartifact.ErrNotApplicable):
		f.Coverage.Set("vendored_npm", check.StatusNotApplicable, opts.RequireComplete, "")
	case vendorErr != nil:
		f.Coverage.Set("vendored_npm", check.StatusFailed, opts.RequireComplete, vendorErr.Error())
	default:
		f.Vendored = vendored.Issues
		f.Coverage.Set("vendored_npm", check.StatusCompleted, opts.RequireComplete, "")
	}
	f.Coverage.SetDuration("vendored_npm", elapsedMS(checkStarted))
	f.Coverage.Set(
		"host_persistence",
		check.StatusDisabled,
		false,
		"host checks are scoped to audit-system",
	)

	checkStarted = time.Now()
	f.Scripts, err = scripts.ScanInstalled(opts.Target)
	if err != nil {
		f.Coverage.Set("install_scripts", check.StatusFailed, false, err.Error())
	} else {
		f.Coverage.Set("install_scripts", check.StatusCompleted, false, "")
	}
	f.Coverage.SetDuration("install_scripts", elapsedMS(checkStarted))

	checkStarted = time.Now()
	f.Drift, err = drift.ScanRepo(opts.Target)
	if err != nil {
		f.Coverage.Set("lockfile_drift", check.StatusFailed, opts.RequireComplete, err.Error())
	} else {
		f.Coverage.Set("lockfile_drift", check.StatusCompleted, opts.RequireComplete, "")
	}
	f.Coverage.SetDuration("lockfile_drift", elapsedMS(checkStarted))

	if opts.FreshnessDays > 0 && opts.Registry != nil {
		checkStarted = time.Now()
		f.Freshness, err = freshness.Check(opts.Target, opts.FreshnessDays, opts.Registry)
		if err != nil {
			f.Coverage.Set("freshness", check.StatusFailed, false, err.Error())
		} else {
			f.Coverage.Set("freshness", check.StatusCompleted, false, "")
		}
		f.Coverage.SetDuration("freshness", elapsedMS(checkStarted))
	} else {
		f.Coverage.Set("freshness", check.StatusDisabled, false, "")
	}

	checkStarted = time.Now()
	if opts.TyposquatDistance > 0 {
		f.Typosquat, err = typosquat.CheckWith(opts.Target, opts.TyposquatDistance)
	} else {
		f.Typosquat, err = typosquat.Check(opts.Target)
	}
	if err != nil {
		f.Coverage.Set("typosquat", check.StatusFailed, opts.RequireComplete, err.Error())
	} else {
		f.Coverage.Set("typosquat", check.StatusCompleted, opts.RequireComplete, "")
	}
	f.Coverage.SetDuration("typosquat", elapsedMS(checkStarted))

	if opts.Signatures {
		checkStarted = time.Now()
		f.Signatures, err = npmsig.Run(opts.Target)
		switch {
		case errors.Is(err, npmsig.ErrNotApplicable):
			f.Coverage.Set("npm_signatures", check.StatusNotApplicable, opts.RequireComplete, "")
		case errors.Is(err, npmsig.ErrUnavailable):
			f.Coverage.Set("npm_signatures", check.StatusIncomplete, opts.RequireComplete, err.Error())
		case err != nil:
			f.Coverage.Set("npm_signatures", check.StatusFailed, opts.RequireComplete, err.Error())
		default:
			f.Coverage.Set("npm_signatures", check.StatusCompleted, opts.RequireComplete, "")
		}
		f.Coverage.SetDuration("npm_signatures", elapsedMS(checkStarted))
	} else {
		f.Coverage.Set("npm_signatures", check.StatusDisabled, false, "")
	}

	if opts.Maintainers && opts.Registry != nil &&
		(opts.MaintainerBaseline != "" || opts.MaintainerBaseDir != "") {
		checkStarted = time.Now()
		if opts.MaintainerBaseline != "" {
			f.Maintainers, err = maintainer.CheckFile(
				opts.Target, opts.Registry, opts.MaintainerBaseline, opts.AcceptMaintainers,
			)
		} else {
			f.Maintainers, err = maintainer.Check(
				opts.Target, opts.Registry, opts.MaintainerBaseDir, opts.AcceptMaintainers,
			)
		}
		if err != nil {
			f.Coverage.Set("maintainers", check.StatusFailed, opts.RequireComplete, err.Error())
		} else {
			f.Coverage.Set("maintainers", check.StatusCompleted, opts.RequireComplete, "")
		}
		f.Coverage.SetDuration("maintainers", elapsedMS(checkStarted))
	} else {
		f.Coverage.Set("maintainers", check.StatusDisabled, false, "")
	}

	// Availability is independent of whether the scan returned findings —
	// a clean OSV scan also returns no hits but is "available".
	_, osvVersion, locateErr := osv.Locate(opts.BinDir)
	f.OSVAvailable = locateErr == nil
	if !f.OSVAvailable {
		f.Helpers["osv-scanner"] = "unavailable"
		if opts.RequireOSV {
			f.Coverage.Set("osv", check.StatusIncomplete, true, "osv-scanner is required but unavailable")
		} else {
			f.Coverage.Set("osv", check.StatusIncomplete, false, "osv-scanner is unavailable")
		}
		f.OSV, f.Drift, f.Suppressed = sourcePolicy.Apply(f.OSV, f.Drift)
		return f, nil
	}
	f.Helpers["osv-scanner"] = osvVersion
	checkStarted = time.Now()
	osvHits, osvErr := osv.Scan(opts.BinDir, opts.Target)
	if err := applyOSVResult(&f, osvHits, osvErr); err != nil {
		f.Coverage.Set("osv", check.StatusFailed, opts.RequireOSV, err.Error())
		f.Coverage.SetDuration("osv", elapsedMS(checkStarted))
		f.OSV, f.Drift, f.Suppressed = sourcePolicy.Apply(f.OSV, f.Drift)
		return f, nil
	}
	if f.OSVStatus == OSVNotApplicable {
		f.Coverage.Set("osv", check.StatusNotApplicable, opts.RequireOSV, "")
	} else {
		f.Coverage.Set("osv", check.StatusCompleted, opts.RequireOSV, "")
	}
	f.Coverage.SetDuration("osv", elapsedMS(checkStarted))
	f.OSV, f.Drift, f.Suppressed = sourcePolicy.Apply(f.OSV, f.Drift)
	return f, nil
}

func applyOSVResult(f *Findings, hits []osv.PackageVuln, err error) error {
	if errors.Is(err, osv.ErrNoPackageSources) {
		f.OSVStatus = OSVNotApplicable
		return nil
	}
	if err != nil {
		return fmt.Errorf("scan: OSV advisory check: %w", err)
	}
	f.OSVStatus = OSVCompleted
	if hits != nil {
		f.OSV = hits
	}
	return nil
}

func elapsedMS(start time.Time) int64 {
	duration := time.Since(start).Milliseconds()
	if duration == 0 {
		return 1
	}
	return duration
}

// SortFindings establishes the machine-report ordering contract.
func SortFindings(f *Findings) {
	sort.Slice(f.Manifest, func(i, j int) bool {
		return f.Manifest[i].File < f.Manifest[j].File ||
			(f.Manifest[i].File == f.Manifest[j].File &&
				f.Manifest[i].Name < f.Manifest[j].Name)
	})
	sort.Slice(f.Lockfile, func(i, j int) bool {
		return f.Lockfile[i].File < f.Lockfile[j].File ||
			(f.Lockfile[i].File == f.Lockfile[j].File &&
				f.Lockfile[i].Name < f.Lockfile[j].Name)
	})
	sort.Slice(f.OSV, func(i, j int) bool {
		if f.OSV[i].SourcePath != f.OSV[j].SourcePath {
			return f.OSV[i].SourcePath < f.OSV[j].SourcePath
		}
		if f.OSV[i].Name != f.OSV[j].Name {
			return f.OSV[i].Name < f.OSV[j].Name
		}
		return f.OSV[i].Version < f.OSV[j].Version
	})
	for i := range f.OSV {
		sort.Strings(f.OSV[i].IDs)
		sort.Slice(f.OSV[i].Advisories, func(a, b int) bool {
			return f.OSV[i].Advisories[a].ID < f.OSV[i].Advisories[b].ID
		})
	}
	sort.Slice(f.Payloads, func(i, j int) bool {
		return f.Payloads[i].Path < f.Payloads[j].Path
	})
	sort.Slice(f.Scripts, func(i, j int) bool {
		return f.Scripts[i].Path < f.Scripts[j].Path
	})
	sort.Slice(f.Freshness, func(i, j int) bool {
		if f.Freshness[i].Name != f.Freshness[j].Name {
			return f.Freshness[i].Name < f.Freshness[j].Name
		}
		return f.Freshness[i].Version < f.Freshness[j].Version
	})
	sort.Slice(f.Typosquat, func(i, j int) bool {
		return f.Typosquat[i].Source < f.Typosquat[j].Source ||
			(f.Typosquat[i].Source == f.Typosquat[j].Source &&
				f.Typosquat[i].Name < f.Typosquat[j].Name)
	})
	sort.Slice(f.Signatures, func(i, j int) bool {
		return f.Signatures[i].Name < f.Signatures[j].Name ||
			(f.Signatures[i].Name == f.Signatures[j].Name &&
				f.Signatures[i].Version < f.Signatures[j].Version)
	})
	sort.Slice(f.Vendored, func(i, j int) bool {
		if f.Vendored[i].Package != f.Vendored[j].Package {
			return f.Vendored[i].Package < f.Vendored[j].Package
		}
		if f.Vendored[i].Path != f.Vendored[j].Path {
			return f.Vendored[i].Path < f.Vendored[j].Path
		}
		return f.Vendored[i].Code < f.Vendored[j].Code
	})
	sort.Slice(f.Maintainers, func(i, j int) bool {
		return f.Maintainers[i].Name < f.Maintainers[j].Name
	})
	sort.Slice(f.Drift, func(i, j int) bool {
		return f.Drift[i].ManifestFile < f.Drift[j].ManifestFile ||
			(f.Drift[i].ManifestFile == f.Drift[j].ManifestFile &&
				f.Drift[i].Name < f.Drift[j].Name)
	})
	sort.Slice(f.Suppressed, func(i, j int) bool {
		if f.Suppressed[i].Kind != f.Suppressed[j].Kind {
			return f.Suppressed[i].Kind < f.Suppressed[j].Kind
		}
		if f.Suppressed[i].Package != f.Suppressed[j].Package {
			return f.Suppressed[i].Package < f.Suppressed[j].Package
		}
		return f.Suppressed[i].AdvisoryID < f.Suppressed[j].AdvisoryID
	})
}
