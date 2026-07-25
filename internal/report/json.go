package report

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/noeljackson/supplychain/internal/check"
	"github.com/noeljackson/supplychain/internal/drift"
	"github.com/noeljackson/supplychain/internal/freshness"
	"github.com/noeljackson/supplychain/internal/ioc"
	"github.com/noeljackson/supplychain/internal/maintainer"
	"github.com/noeljackson/supplychain/internal/manifest"
	"github.com/noeljackson/supplychain/internal/npmsig"
	"github.com/noeljackson/supplychain/internal/osv"
	"github.com/noeljackson/supplychain/internal/policy"
	"github.com/noeljackson/supplychain/internal/scan"
	"github.com/noeljackson/supplychain/internal/scripts"
	"github.com/noeljackson/supplychain/internal/typosquat"
	"github.com/noeljackson/supplychain/internal/update"
)

const (
	SchemaVersion   = 1
	ExitClean       = 0
	ExitFindings    = 1
	ExitUsage       = 2
	ExitOperational = 3
)

type ScannerIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type PolicyIdentity struct {
	Mode           string          `json:"mode"`
	FailOnAdvisory bool            `json:"fail_on_advisory"`
	Source         policy.Identity `json:"source"`
}

type Outcome struct {
	Status                  string `json:"status"`
	ExitCode                int    `json:"exit_code"`
	HasFindings             bool   `json:"has_findings"`
	HasSupplyChainFindings  bool   `json:"has_supply_chain_findings"`
	HasAdvisoryFindings     bool   `json:"has_advisory_findings"`
	HasCoverageGaps         bool   `json:"has_coverage_gaps"`
	HasRequiredCoverageGaps bool   `json:"has_required_coverage_gaps"`
}

type Diagnostic struct {
	Check    string       `json:"check"`
	Status   check.Status `json:"status"`
	Required bool         `json:"required"`
	Message  string       `json:"message"`
}

type Timings struct {
	TotalMS int64 `json:"total_ms"`
}

type FindingSet struct {
	Manifest    []manifest.ManifestHit `json:"manifest_ioc"`
	Lockfile    []manifest.LockHit     `json:"lockfile_ioc"`
	OSV         []osv.PackageVuln      `json:"osv"`
	Payloads    []ioc.PayloadHit       `json:"payload_ioc"`
	Scripts     []scripts.Hit          `json:"install_scripts"`
	Freshness   []freshness.Hit        `json:"freshness"`
	Typosquat   []typosquat.Hit        `json:"typosquat"`
	Signatures  []npmsig.Hit           `json:"npm_signatures"`
	Maintainers []maintainer.Hit       `json:"maintainers"`
	Drift       []drift.Hit            `json:"lockfile_drift"`
	Suppressed  []policy.Suppressed    `json:"suppressed"`
}

// Envelope is the versioned machine-readable contract for a source scan.
type Envelope struct {
	SchemaVersion int                     `json:"schema_version"`
	Command       string                  `json:"command"`
	Scanner       ScannerIdentity         `json:"scanner"`
	Target        string                  `json:"target"`
	Policy        PolicyIdentity          `json:"policy"`
	IOCSnapshot   update.SnapshotIdentity `json:"ioc_snapshot"`
	Helpers       map[string]string       `json:"helpers"`
	Outcome       Outcome                 `json:"outcome"`
	Checks        check.Coverage          `json:"checks"`
	Timings       Timings                 `json:"timings"`
	Diagnostics   []Diagnostic            `json:"diagnostics"`
	Findings      FindingSet              `json:"findings"`
}

// NewEnvelope creates a deterministic source-scan report.
func NewEnvelope(f scan.Findings, opts Options) Envelope {
	scan.SortFindings(&f)
	code := exitCode(f, opts)
	status := "clean"
	switch {
	case code == ExitOperational:
		status = "incomplete"
	case code == ExitFindings:
		status = "findings"
	case f.HasAdvisoryHits() || f.HasCoverageGaps() || len(f.Suppressed) > 0:
		status = "warning"
	}
	mode := "default"
	if opts.FailOnAdvisory {
		mode = "strict"
	}
	version := opts.ScannerVersion
	if version == "" {
		version = "unknown"
	}
	return Envelope{
		SchemaVersion: SchemaVersion,
		Command:       "scan",
		Scanner:       ScannerIdentity{Name: "supplychain", Version: version},
		Target:        f.Target,
		Policy: PolicyIdentity{
			Mode:           mode,
			FailOnAdvisory: opts.FailOnAdvisory,
			Source:         f.Policy,
		},
		IOCSnapshot: opts.IOCSnapshot,
		Helpers:     copyMap(f.Helpers),
		Outcome: Outcome{
			Status:                  status,
			ExitCode:                code,
			HasFindings:             f.HasHits(),
			HasSupplyChainFindings:  f.HasSupplyChainHits(),
			HasAdvisoryFindings:     f.HasAdvisoryHits(),
			HasCoverageGaps:         f.HasCoverageGaps(),
			HasRequiredCoverageGaps: f.HasRequiredCoverageGaps(),
		},
		Checks:      f.Coverage,
		Timings:     Timings{TotalMS: f.DurationMS},
		Diagnostics: diagnostics(f.Coverage),
		Findings: FindingSet{
			Manifest:    nonNil(f.Manifest),
			Lockfile:    nonNil(f.Lockfile),
			OSV:         nonNil(f.OSV),
			Payloads:    nonNil(f.Payloads),
			Scripts:     nonNil(f.Scripts),
			Freshness:   nonNil(f.Freshness),
			Typosquat:   nonNil(f.Typosquat),
			Signatures:  nonNil(f.Signatures),
			Maintainers: nonNil(f.Maintainers),
			Drift:       nonNil(f.Drift),
			Suppressed:  nonNil(f.Suppressed),
		},
	}
}

func JSON(w io.Writer, f scan.Findings, opts Options) int {
	envelope := NewEnvelope(f, opts)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(envelope)
	return envelope.Outcome.ExitCode
}

func exitCode(f scan.Findings, opts Options) int {
	if f.HasRequiredCoverageGaps() {
		return ExitOperational
	}
	if f.HasSupplyChainHits() || (opts.FailOnAdvisory && f.HasAdvisoryHits()) {
		return ExitFindings
	}
	return ExitClean
}

func diagnostics(coverage check.Coverage) []Diagnostic {
	names := make([]string, 0, len(coverage))
	for name, result := range coverage {
		if result.Diagnostic != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	out := make([]Diagnostic, 0, len(names))
	for _, name := range names {
		result := coverage[name]
		out = append(out, Diagnostic{
			Check:    name,
			Status:   result.Status,
			Required: result.Required,
			Message:  result.Diagnostic,
		})
	}
	return out
}

func nonNil[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}

func copyMap(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
