package cmd

import (
	"testing"

	"github.com/noeljackson/supplychain/internal/report"
)

func TestCombinedExitContract(t *testing.T) {
	tests := []struct {
		name  string
		codes []int
		want  int
	}{
		{name: "clean", codes: []int{0, 0}, want: report.ExitClean},
		{name: "findings", codes: []int{0, 1}, want: report.ExitFindings},
		{name: "usage", codes: []int{0, 2}, want: report.ExitUsage},
		{name: "operational wins", codes: []int{1, 2, 3}, want: report.ExitOperational},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if got := combinedExit(testCase.codes...); got != testCase.want {
				t.Fatalf("combinedExit(%v) = %d, want %d", testCase.codes, got, testCase.want)
			}
		})
	}
}
