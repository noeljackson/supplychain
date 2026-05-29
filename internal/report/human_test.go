package report

import (
	"bytes"
	"strings"
	"testing"

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
	if code := Human(&out, f, Options{}); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(out.String(), "err supply-chain indicators") {
		t.Fatalf("missing supply-chain header in output:\n%s", out.String())
	}
}
