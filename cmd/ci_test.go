package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/noeljackson/supplychain/internal/report"
)

func TestCIRefreshOSMRequiresToken(t *testing.T) {
	t.Setenv("SUPPLYCHAIN_OSM_TOKEN", "")
	globals := &Globals{
		DataDir: t.TempDir(),
		BinDir:  t.TempDir(),
	}
	if exit := cmdCI(globals, []string{"--refresh-osm", t.TempDir()}); exit != report.ExitOperational {
		t.Fatalf("exit = %d, want %d", exit, report.ExitOperational)
	}
}

func TestCIRejectsRepositoryPolicyAlongsideTrustedBundle(t *testing.T) {
	policyDir := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(policyDir, "source-policy.json"),
		[]byte(`{"schema_version":1,"advisories":{"minimum_severity":"high","only_fixed":true},"exceptions":[]}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	globals := &Globals{
		DataDir:      t.TempDir(),
		BinDir:       t.TempDir(),
		SourcePolicy: ".supplychain/source-policy.json",
	}
	exit := cmdCI(globals, []string{
		"--trusted-policy-dir=" + policyDir,
		t.TempDir(),
	})
	if exit != report.ExitUsage {
		t.Fatalf("exit = %d, want %d", exit, report.ExitUsage)
	}
}
