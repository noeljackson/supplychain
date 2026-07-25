package cmd

import "testing"

func TestDoctorProfilesDeclareRequiredCapabilities(t *testing.T) {
	strict, ok := doctorRequirements("strict")
	if !ok || !strict["osv-scanner"] || !strict["gitleaks"] || !strict["zizmor"] {
		t.Fatalf("strict profile requirements = %v", strict)
	}
	if _, ok := doctorRequirements("surprise"); ok {
		t.Fatal("unknown profile should be rejected")
	}
}

func TestDoctorHealthFailsOnlyRequiredChecks(t *testing.T) {
	if !doctorHealthy([]doctorCheck{{Name: "optional", Status: "missing"}}) {
		t.Fatal("optional missing helper should not fail health")
	}
	if doctorHealthy([]doctorCheck{{Name: "required", Status: "missing", Required: true}}) {
		t.Fatal("required missing helper should fail health")
	}
}
