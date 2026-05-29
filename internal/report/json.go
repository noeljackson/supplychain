package report

import (
	"encoding/json"
	"io"

	"github.com/noeljackson/supplychain/internal/scan"
)

type jsonReport struct {
	Target             string        `json:"target"`
	OSVAvailable       bool          `json:"osv_available"`
	HasHits            bool          `json:"has_hits"`
	HasSupplyChainHits bool          `json:"has_supply_chain_hits"`
	HasAdvisoryHits    bool          `json:"has_advisory_hits"`
	Findings           scan.Findings `json:"findings"`
}

func JSON(w io.Writer, f scan.Findings, opts Options) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(jsonReport{
		Target:             f.Target,
		OSVAvailable:       f.OSVAvailable,
		HasHits:            f.HasHits(),
		HasSupplyChainHits: f.HasSupplyChainHits(),
		HasAdvisoryHits:    f.HasAdvisoryHits(),
		Findings:           f,
	})
	if f.HasSupplyChainHits() || (opts.FailOnAdvisory && f.HasAdvisoryHits()) {
		return 1
	}
	return 0
}
