package check

import "testing"

func TestCoverageGaps(t *testing.T) {
	coverage := Coverage{}
	coverage.Set("completed", StatusCompleted, true, "")
	coverage.Set("optional", StatusIncomplete, false, "fixture")
	if !coverage.HasGaps() {
		t.Fatal("optional incomplete check should be a coverage gap")
	}
	if coverage.HasRequiredGaps() {
		t.Fatal("optional incomplete check should not be a required gap")
	}
	coverage.Set("required", StatusFailed, true, "fixture")
	if !coverage.HasRequiredGaps() {
		t.Fatal("required failed check should be a required gap")
	}
}
