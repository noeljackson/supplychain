package cmd

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/noeljackson/supplychain/internal/eol"
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

func TestCIRefreshEOLFailsClosedWhenUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	t.Setenv(eol.EnvBaseURL, server.URL)
	globals := &Globals{DataDir: t.TempDir(), BinDir: t.TempDir()}
	if exit := cmdCI(globals, []string{"--refresh-eol", t.TempDir()}); exit != report.ExitOperational {
		t.Fatalf("exit = %d, want %d", exit, report.ExitOperational)
	}
}
