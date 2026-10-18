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

func TestCIOSMTokenFileRequiresRefresh(t *testing.T) {
	globals := &Globals{
		DataDir: t.TempDir(),
		BinDir:  t.TempDir(),
	}
	if exit := cmdCI(globals, []string{"--osm-token-file=token", t.TempDir()}); exit != report.ExitUsage {
		t.Fatalf("exit = %d, want %d", exit, report.ExitUsage)
	}
}
