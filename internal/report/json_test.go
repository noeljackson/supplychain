package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/noeljackson/supplychain/internal/check"
	"github.com/noeljackson/supplychain/internal/policy"
	"github.com/noeljackson/supplychain/internal/scan"
	"github.com/noeljackson/supplychain/internal/update"
)

func TestJSONNamesMissingOfflineEcosystemsWithoutParsingMessage(t *testing.T) {
	findings := scan.Findings{Coverage: check.Coverage{"osv": {
		Status: check.StatusFailed, Required: true, Diagnostic: "bundle needs more databases",
		Code: "offline-databases-missing", Ecosystems: []string{"Maven", "RubyGems"},
	}}}
	var output bytes.Buffer
	if code := JSON(&output, findings, Options{FailOnAdvisory: true}); code != ExitOperational {
		t.Fatalf("exit = %d, want operational failure", code)
	}
	var report struct {
		Diagnostics []Diagnostic `json:"diagnostics"`
	}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Diagnostics) != 1 || report.Diagnostics[0].Code != "offline-databases-missing" ||
		len(report.Diagnostics[0].Ecosystems) != 2 || report.Diagnostics[0].Ecosystems[1] != "RubyGems" {
		t.Fatalf("structured diagnostics missing: %+v", report.Diagnostics)
	}
}

func TestJSONV1GoldenAndOperationalExit(t *testing.T) {
	findings := scan.Findings{
		Target: "/repo",
		Coverage: check.Coverage{
			"osv": {
				Status:     check.StatusIncomplete,
				Required:   true,
				Diagnostic: "missing helper",
				DurationMS: 7,
			},
		},
		Policy: policy.Identity{
			Name:   "repository-source-policy",
			Path:   ".supplychain/source-policy.json",
			SHA256: "policy-digest",
		},
		Helpers:    map[string]string{"osv-scanner": "unavailable"},
		DurationMS: 42,
	}
	options := Options{
		FailOnAdvisory: true,
		ScannerVersion: "v1.2.3",
		IOCSnapshot: update.SnapshotIdentity{
			Source:         "embedded",
			SchemaVersion:  1,
			GeneratedAt:    "2026-07-25T00:00:00Z",
			SourceRevision: "abc123",
			ManifestSHA256: "ioc-digest",
		},
	}
	var output bytes.Buffer
	if code := JSON(&output, findings, options); code != ExitOperational {
		t.Fatalf("exit code = %d, want %d", code, ExitOperational)
	}
	golden, err := os.ReadFile(filepath.Join("testdata", "scan-v1.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if output.String() != string(golden) {
		t.Fatalf("JSON contract changed:\n--- got ---\n%s\n--- want ---\n%s", output.String(), golden)
	}
}
