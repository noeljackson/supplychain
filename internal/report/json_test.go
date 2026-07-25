package report

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/noeljackson/supplychain/internal/check"
	"github.com/noeljackson/supplychain/internal/policy"
	"github.com/noeljackson/supplychain/internal/scan"
	"github.com/noeljackson/supplychain/internal/update"
)

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
