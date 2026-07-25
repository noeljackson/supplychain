// Package check models whether an individual scanner check actually ran.
package check

// Status describes coverage independently from whether a check found anything.
type Status string

const (
	StatusDisabled      Status = "disabled"
	StatusNotApplicable Status = "not_applicable"
	StatusCompleted     Status = "completed"
	StatusIncomplete    Status = "incomplete"
	StatusFailed        Status = "failed"
)

// Result is the coverage outcome for one named check.
type Result struct {
	Status     Status `json:"status"`
	Required   bool   `json:"required"`
	Diagnostic string `json:"diagnostic,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

// Coverage maps stable check identifiers to their result.
type Coverage map[string]Result

// Set records one check result.
func (c Coverage) Set(name string, status Status, required bool, diagnostic string) {
	c[name] = Result{Status: status, Required: required, Diagnostic: diagnostic}
}

// SetDuration records elapsed wall time after Set has established the outcome.
func (c Coverage) SetDuration(name string, durationMS int64) {
	result := c[name]
	result.DurationMS = durationMS
	c[name] = result
}

// HasGaps reports any enabled check that did not complete.
func (c Coverage) HasGaps() bool {
	for _, result := range c {
		if result.Status == StatusIncomplete || result.Status == StatusFailed {
			return true
		}
	}
	return false
}

// HasRequiredGaps reports an incomplete or failed required check.
func (c Coverage) HasRequiredGaps() bool {
	for _, result := range c {
		if result.Required &&
			(result.Status == StatusIncomplete || result.Status == StatusFailed) {
			return true
		}
	}
	return false
}
