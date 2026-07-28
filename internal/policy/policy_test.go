package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noeljackson/supplychain/internal/drift"
	"github.com/noeljackson/supplychain/internal/osv"
)

var policyNow = time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)

func TestLoadRequiresContainedTrackedRegularPolicy(t *testing.T) {
	repo := initPolicyRepo(t)
	writePolicy(t, repo, validPolicy("2026-07-26"))

	loaded, err := Load(repo, "", false, policyNow)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Identity.Path != DefaultPath {
		t.Fatalf("identity = %+v", loaded.Identity)
	}

	untracked := initPolicyRepo(t)
	writePolicyFile(t, untracked, validPolicy("2026-07-26"))
	if _, err := Load(untracked, "", false, policyNow); err == nil ||
		!strings.Contains(err.Error(), "tracked") {
		t.Fatalf("expected untracked rejection, got %v", err)
	}

	outside := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(outside, []byte(validPolicy("2026-07-26")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(repo, outside, false, policyNow); err == nil ||
		!strings.Contains(err.Error(), "contained") {
		t.Fatalf("expected containment rejection, got %v", err)
	}

	real := filepath.Join(repo, ".supplychain", "real.json")
	if err := os.WriteFile(real, []byte(validPolicy("2026-07-26")), 0o600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(repo, DefaultPath)
	if err := os.Remove(policyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.json", policyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(repo, "", false, policyNow); err == nil ||
		!strings.Contains(err.Error(), "non-symlinked") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func TestLoadRejectsMalformedAndExpiredPolicy(t *testing.T) {
	for name, testCase := range map[string]struct {
		body string
		want string
	}{
		"unknown field": {
			`{"schema_version":1,"advisories":{"minimum_severity":"any","surprise":true},"exceptions":[]}`,
			"unknown field",
		},
		"expired": {validPolicy("2026-07-24"), "expired"},
		"oversized": {
			strings.Repeat(" ", maxSize+1),
			"exceeds",
		},
	} {
		t.Run(name, func(t *testing.T) {
			repo := initPolicyRepo(t)
			writePolicy(t, repo, testCase.body)
			_, err := Load(repo, "", false, policyNow)
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("expected %q rejection, got %v", testCase.want, err)
			}
		})
	}
}

func TestLoadAcceptsExplicitTrustedPolicyOutsideTarget(t *testing.T) {
	repo := initPolicyRepo(t)
	outside := filepath.Join(t.TempDir(), "source-policy.json")
	if err := os.WriteFile(outside, []byte(validPolicy("2026-07-26")), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(repo, outside, true, policyNow)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Identity.Name != "trusted-ci-source-policy" ||
		loaded.Identity.Path != "source-policy.json" {
		t.Fatalf("identity = %+v", loaded.Identity)
	}
}

func TestApplyPrecedenceAndSuppressionVisibility(t *testing.T) {
	loaded := Loaded{Document: Document{
		SchemaVersion: 1,
		Advisories: AdvisoryPolicy{
			MinimumSeverity: "high",
			OnlyFixed:       true,
		},
		Exceptions: []Exception{{
			Kind:       "osv",
			Package:    "demo",
			AdvisoryID: "GHSA-critical",
			Reason:     "migration scheduled",
			Owner:      "@security",
			Expires:    "2026-08-01",
		}, {
			Kind:        "drift",
			Package:     "demo",
			DriftReason: "missing-from-lockfile",
			Reason:      "generated fixture",
			Owner:       "@build",
			Expires:     "2026-08-01",
		}},
	}}
	osvHits := []osv.PackageVuln{{
		Name: "demo", Version: "1.0.0", SourcePath: "package-lock.json",
		Advisories: []osv.Advisory{
			{ID: "GHSA-critical", Severity: "critical", FixedVersions: []string{"2.0.0"}},
			{ID: "GHSA-low", Severity: "low", FixedVersions: []string{"1.0.1"}},
			{ID: "GHSA-unfixed", Severity: "high"},
			{ID: "GHSA-unknown", Severity: "unknown", FixedVersions: []string{"1.1.0"}},
		},
	}}
	driftHits := []drift.Hit{
		{Name: "demo", Reason: "missing-from-lockfile"},
		{Name: "other", Reason: "lockfile-out-of-range"},
	}
	keptOSV, keptDrift, suppressed := loaded.Apply(osvHits, driftHits)
	if len(keptOSV) != 1 || len(keptOSV[0].Advisories) != 1 ||
		keptOSV[0].Advisories[0].ID != "GHSA-unknown" {
		t.Fatalf("unexpected kept advisories: %+v", keptOSV)
	}
	if len(keptDrift) != 1 || keptDrift[0].Name != "other" {
		t.Fatalf("unexpected kept drift: %+v", keptDrift)
	}
	if len(suppressed) != 4 {
		t.Fatalf("suppressed = %+v", suppressed)
	}
	for _, item := range suppressed {
		if item.Reason == "" {
			t.Fatalf("suppression disappeared: %+v", item)
		}
	}
}

func initPolicyRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	if err := exec.Command("git", "-C", repo, "init", "-q").Run(); err != nil {
		t.Fatal(err)
	}
	return repo
}

func writePolicy(t *testing.T, repo, body string) {
	t.Helper()
	writePolicyFile(t, repo, body)
	if err := exec.Command("git", "-C", repo, "add", DefaultPath).Run(); err != nil {
		t.Fatal(err)
	}
}

func writePolicyFile(t *testing.T, repo, body string) {
	t.Helper()
	path := filepath.Join(repo, DefaultPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func validPolicy(expiry string) string {
	return `{
	  "schema_version": 1,
	  "advisories": {"minimum_severity": "high", "only_fixed": true},
	  "exceptions": [{
	    "kind": "osv",
	    "advisory_id": "GHSA-demo",
	    "package": "demo",
	    "reason": "migration scheduled",
	    "owner": "@security",
	    "expires": "` + expiry + `"
	  }]
	}`
}
