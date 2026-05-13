package report

import (
	"encoding/json"
	"io"

	"github.com/noeljackson/supplychain/internal/scan"
)

type jsonReport struct {
	Target       string        `json:"target"`
	OSVAvailable bool          `json:"osv_available"`
	HasHits      bool          `json:"has_hits"`
	Findings     scan.Findings `json:"findings"`
}

func JSON(w io.Writer, f scan.Findings) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(jsonReport{
		Target:       f.Target,
		OSVAvailable: f.OSVAvailable,
		HasHits:      f.HasHits(),
		Findings:     f,
	})
	if f.HasHits() {
		return 1
	}
	return 0
}
