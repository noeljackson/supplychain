package cmd

import (
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
