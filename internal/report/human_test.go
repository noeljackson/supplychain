package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/noeljackson/supplychain/internal/check"
	"github.com/noeljackson/supplychain/internal/eol"
	"github.com/noeljackson/supplychain/internal/manifest"
	"github.com/noeljackson/supplychain/internal/osv"
	"github.com/noeljackson/supplychain/internal/scan"
	"github.com/noeljackson/supplychain/internal/vendorartifact"
)

func TestHumanAdvisoryOnlyDoesNotFailByDefault(t *testing.T) {
	f := scan.Findings{
		Target:       "/repo",
		OSVAvailable: true,
		OSV:          []osv.PackageVuln{{Name: "pkg", Version: "1.0.0", IDs: []string{"GHSA-test"}, SourcePath: "/repo/package-lock.json"}},
	}

	var out bytes.Buffer
	if code := Human(&out, f, Options{}); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	got := out.String()
	if !strings.Contains(got, "warn dependency advisory/audit findings") {
		t.Fatalf("missing advisory header in output:\n%s", got)
	}
	if strings.Contains(got, "err supply-chain") {
		t.Fatalf("advisory-only output should not use supply-chain error header:\n%s", got)
	}
}

func TestHumanFailOnAdvisory(t *testing.T) {
	f := scan.Findings{
		Target:       "/repo",
		OSVAvailable: true,
		OSV:          []osv.PackageVuln{{Name: "pkg", Version: "1.0.0", IDs: []string{"GHSA-test"}, SourcePath: "/repo/package-lock.json"}},
	}

	var out bytes.Buffer
	if code := Human(&out, f, Options{FailOnAdvisory: true}); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestHumanSupplyChainHitFails(t *testing.T) {
	f := scan.Findings{
		Target:   "/repo",
		Manifest: []manifest.ManifestHit{{File: "/repo/package.json", Section: "dependencies", Name: "pkg", Range: "^1", BadVersion: "1.0.0", Reason: "range-includes"}},
	}

	var out bytes.Buffer
	if code := Human(&out, f, Options{}); code != ExitFindings {
		t.Fatalf("exit code = %d, want %d", code, ExitFindings)
	}
	if !strings.Contains(out.String(), "err supply-chain indicators") {
		t.Fatalf("missing supply-chain header in output:\n%s", out.String())
	}
}

func TestHumanRendersVendoredNPMFailure(t *testing.T) {
	f := scan.Findings{
		Target: "/repo",
		Vendored: []vendorartifact.Issue{{
			Code: "vendored-digest-mismatch", Package: "htmx.org@2.0.10",
			Path: "vendor/htmx.min.js", Message: "checked-in artifact drifted",
		}},
	}
	var out bytes.Buffer
	if code := Human(&out, f, Options{}); code != ExitFindings {
		t.Fatalf("exit code = %d, want %d", code, ExitFindings)
	}
	for _, want := range []string{"Vendored npm artifacts", "htmx.org@2.0.10", "vendored-digest-mismatch"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in output:\n%s", want, out.String())
		}
	}
}

func TestHumanExplainsOSVNotApplicable(t *testing.T) {
	f := scan.Findings{
		Target:       "/docs-only",
		OSVAvailable: true,
		OSVStatus:    scan.OSVNotApplicable,
	}
	var out bytes.Buffer
	if code := Human(&out, f, Options{}); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "not applicable") {
		t.Fatalf("missing not-applicable explanation:\n%s", out.String())
	}
}

func TestHumanRequiredCoverageGapFails(t *testing.T) {
	f := scan.Findings{Target: "/repo", Coverage: check.Coverage{}}
	f.Coverage.Set("lockfile_ioc", check.StatusFailed, true, "malformed lockfile")
	var out bytes.Buffer
	if code := Human(&out, f, Options{}); code != ExitOperational {
		t.Fatalf("exit code = %d, want %d", code, ExitOperational)
	}
	for _, want := range []string{"required scan coverage incomplete", "lockfile_ioc", "malformed lockfile"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in output:\n%s", want, out.String())
		}
	}
}

func TestHumanOptionalCoverageGapWarns(t *testing.T) {
	f := scan.Findings{Target: "/repo", Coverage: check.Coverage{}}
	f.Coverage.Set("freshness", check.StatusIncomplete, false, "registry unavailable")
	var out bytes.Buffer
	if code := Human(&out, f, Options{}); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "optional scan coverage incomplete") {
		t.Fatalf("missing optional coverage warning:\n%s", out.String())
	}
}

func TestHumanRuntimeEndOfLifeFailsStrictAndStaleOnlyWarns(t *testing.T) {
	eolFinding := eol.Hit{Product: "nodejs", Cycle: "20", Version: "20", Path: ".github/workflows/ci.yml",
		Line: 9, Source: "node-version", Reason: eol.ReasonEndOfLife, Detail: "nodejs 20 reached end of life on 2026-04-30"}
	stale := eol.Hit{Product: "go", Cycle: "1.26", Version: "1.26.3", Path: "sdk/go.mod", Line: 3,
		Source: "go directive", Reason: eol.ReasonBehindLatest, Detail: "go 1.26.3 trails 1.26.10"}

	var out bytes.Buffer
	f := scan.Findings{Target: "/repo", OSVAvailable: true, RuntimeEOL: []eol.Hit{eolFinding}, RuntimeStale: []eol.Hit{stale}}
	if code := Human(&out, f, Options{FailOnAdvisory: true}); code != ExitFindings {
		t.Fatalf("strict exit = %d, want %d\n%s", code, ExitFindings, out.String())
	}
	for _, want := range []string{
		"End-of-life runtimes, toolchains and base images (fails strict):",
		".github/workflows/ci.yml:9  node-version — nodejs 20 reached end of life on 2026-04-30",
		"Stale runtimes, toolchains, base images and apt snapshots (warning, 1):",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in:\n%s", want, out.String())
		}
	}

	out.Reset()
	f = scan.Findings{Target: "/repo", OSVAvailable: true, RuntimeStale: []eol.Hit{stale},
		Coverage: check.Coverage{}}
	if code := Human(&out, f, Options{FailOnAdvisory: true}); code != ExitClean {
		t.Fatalf("stale-only exit = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "ok  clean") || !strings.Contains(out.String(), "sdk/go.mod:3") {
		t.Fatalf("stale-only output:\n%s", out.String())
	}

	out.Reset()
	f = scan.Findings{Target: "/repo", OSVAvailable: true, Coverage: check.Coverage{}}
	f.Coverage.Set("runtime_eol", check.StatusDisabled, false, "end-of-life data for go is missing")
	Human(&out, f, Options{})
	if !strings.Contains(out.String(), "note: end-of-life check skipped — end-of-life data for go is missing") {
		t.Fatalf("missing-data note absent:\n%s", out.String())
	}
}
