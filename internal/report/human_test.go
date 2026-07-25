package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/noeljackson/supplychain/internal/check"
	"github.com/noeljackson/supplychain/internal/manifest"
	"github.com/noeljackson/supplychain/internal/osv"
	"github.com/noeljackson/supplychain/internal/scan"
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
