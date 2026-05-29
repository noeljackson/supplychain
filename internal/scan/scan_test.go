package scan

import (
	"testing"

	"github.com/noeljackson/supplychain/internal/drift"
	"github.com/noeljackson/supplychain/internal/manifest"
	"github.com/noeljackson/supplychain/internal/osv"
)

func TestFindingClassification(t *testing.T) {
	advisoryOnly := Findings{
		OSV:   []osv.PackageVuln{{Name: "pkg", Version: "1.0.0"}},
		Drift: []drift.Hit{{Name: "pkg", Reason: "missing-from-lockfile"}},
	}
	if advisoryOnly.HasSupplyChainHits() {
		t.Fatal("OSV/drift advisories should not count as supply-chain indicators")
	}
	if !advisoryOnly.HasAdvisoryHits() {
		t.Fatal("expected advisory hits")
	}
	if !advisoryOnly.HasHits() {
		t.Fatal("expected HasHits to preserve any non-info finding semantics")
	}

	iocHit := Findings{
		Manifest: []manifest.ManifestHit{{Name: "pkg", BadVersion: "1.0.0"}},
	}
	if !iocHit.HasSupplyChainHits() {
		t.Fatal("IOC manifest hits should count as supply-chain indicators")
	}
	if iocHit.HasAdvisoryHits() {
		t.Fatal("IOC-only finding should not count as advisory-only")
	}
}
