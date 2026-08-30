package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"sort"

	"github.com/noeljackson/supplychain/internal/ioc"
	"github.com/noeljackson/supplychain/internal/manifest"
)

// probeManifest scans the tracked fixture corpus and dumps each hit as JSON.
//
// Emitting the marshalled struct rather than a hand-rolled summary pins the
// wire format as well as the matching semantics: ManifestHit carries no json
// tags, so its field names are part of the report contract by accident and the
// Rust port has to reproduce them exactly.
//
// The registry client is deliberately nil. Resolution enrichment reaches out to
// the npm registry, which would make the probe non-hermetic; it is gated
// separately once the Rust registry client lands.
func probeManifest() error {
	open := func(name string) (fs.File, error) { return os.DirFS("iocs").Open(name) }
	iocs, err := ioc.LoadPackages(open)
	if err != nil {
		return err
	}
	blocked, err := ioc.LoadList(open, "blocked-package-names.txt")
	if err != nil {
		return err
	}

	hits, err := manifest.ScanRepo("parity/fixtures/manifests", iocs, blocked, nil)
	if err != nil {
		return err
	}

	// Go map iteration is randomised and SortFindings orders only by
	// (File, Name), which leaves ties among sections and indicator versions
	// unordered. Sort on the whole record so the probe compares sets.
	lines := make([]string, 0, len(hits))
	for _, hit := range hits {
		encoded, err := json.Marshal(hit)
		if err != nil {
			return err
		}
		lines = append(lines, string(encoded))
	}
	sort.Strings(lines)
	for _, line := range lines {
		fmt.Println(line)
	}
	return nil
}
