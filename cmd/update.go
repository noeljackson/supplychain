package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/noeljackson/supplychain/internal/osm"
	"github.com/noeljackson/supplychain/internal/osv"
	"github.com/noeljackson/supplychain/internal/report"
	"github.com/noeljackson/supplychain/internal/update"
)

func cmdUpdate(g *Globals, args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: supplychain update")
		return report.ExitUsage
	}
	fmt.Println("==> refreshing IOC data")
	if err := update.IOCsForce(g.DataDir); err != nil {
		fmt.Fprintln(os.Stderr, "IOC update failed:", err)
		return report.ExitOperational
	}
	healthy := true
	fmt.Println("==> checking osv-scanner")
	if err := osv.Ensure(g.BinDir); err != nil {
		fmt.Fprintln(os.Stderr, "osv-scanner install failed:", err)
		healthy = false
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
		healthy = false
	default:
		fmt.Printf("    cached %d entries (+%d skipped as ranges/unparseable)\n", added, ignored)
	}
	if !healthy {
		return report.ExitOperational
	}
	fmt.Println("ok")
	return report.ExitClean
}
