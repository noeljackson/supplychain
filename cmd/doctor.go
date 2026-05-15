package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/noeljackson/supplychain/internal/osm"
	"github.com/noeljackson/supplychain/internal/osv"
	"github.com/noeljackson/supplychain/internal/update"
)

func cmdDoctor(g *Globals, _ []string) int {
	fmt.Println("supplychain", Version)
	fmt.Println("data-dir:", g.DataDir)
	fmt.Println("bin-dir: ", g.BinDir)

	// IOC data freshness
	iocsDir := filepath.Join(g.DataDir, "iocs")
	if _, err := os.Stat(iocsDir); err == nil {
		age := update.IOCAgeHuman(g.DataDir)
		fmt.Println("iocs:    user override active —", age, "since last refresh")
	} else {
		fmt.Println("iocs:    using embedded defaults (no override)")
	}

	// osv-scanner
	if path, ver, err := osv.Locate(g.BinDir); err == nil {
		fmt.Printf("osv:     %s (%s)\n", path, ver)
	} else {
		fmt.Println("osv:     missing — run 'supplychain update' to install")
	}

	// OSM (OpenSourceMalware) enrichment
	if osm.Token() == "" {
		fmt.Println("osm:     disabled — set SUPPLYCHAIN_OSM_TOKEN to enable (free tier; non-commercial use only)")
	} else {
		cache, _ := osm.LoadCache(osm.CachePath(g.DataDir))
		if cache == nil {
			fmt.Println("osm:     token present but no cache yet — run 'supplychain update'")
		} else {
			fmt.Printf("osm:     %d cached IOCs (last fetch %s)\n", len(cache.Entries), cache.FetchedAt.Format("2006-01-02 15:04Z"))
		}
	}

	// PATH
	if onPath(g.BinDir) {
		fmt.Println("PATH:    ok")
	} else {
		fmt.Printf("PATH:    warn — %s is not in PATH\n", g.BinDir)
	}
	return 0
}

func onPath(dir string) bool {
	for _, p := range strings.Split(os.Getenv("PATH"), string(os.PathListSeparator)) {
		if p == dir {
			return true
		}
	}
	return false
}
