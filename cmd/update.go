package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/noeljackson/supplychain/internal/osm"
	"github.com/noeljackson/supplychain/internal/osv"
	"github.com/noeljackson/supplychain/internal/update"
)

func cmdUpdate(g *Globals, _ []string) int {
	fmt.Println("==> refreshing IOC data")
	if err := update.IOCsForce(g.DataDir); err != nil {
		fmt.Fprintln(os.Stderr, "IOC update failed:", err)
		return 1
	}
	fmt.Println("==> checking osv-scanner")
	if err := osv.Ensure(g.BinDir); err != nil {
		fmt.Fprintln(os.Stderr, "osv-scanner install failed:", err)
		// Non-fatal: scans still run, OSV section will be skipped.
	}
	fmt.Println("==> refreshing OSM (OpenSourceMalware) cache")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	skipped, added, ignored, err := osm.Refresh(ctx, g.DataDir, []string{"npm"})
	switch {
	case skipped:
		fmt.Println("    skipped — SUPPLYCHAIN_OSM_TOKEN not set")
	case err != nil:
		fmt.Fprintln(os.Stderr, "    OSM refresh failed:", err)
	default:
		fmt.Printf("    cached %d entries (+%d skipped as ranges/unparseable)\n", added, ignored)
	}
	fmt.Println("ok")
	return 0
}
