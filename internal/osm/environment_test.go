package osm

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// The test binary doubles as a child tool: it records whether it inherited the
// OSM token and exits.
func init() {
	report := os.Getenv("TEST_OSM_CHILD_ENV_REPORT")
	if os.Getenv("GO_WANT_OSM_CHILD_ENV_HELPER") != "1" || report == "" {
		return
	}
	_, present := os.LookupEnv(envToken)
	if err := os.WriteFile(report, []byte(strconv.FormatBool(present)), 0o600); err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

// childSeesToken starts the child tool the two ways supplychain starts tools:
// inheriting the environment (Cmd.Env nil), and with an explicit environment
// built from os.Environ() at start, as the gitleaks, syft and grype calls do.
func childSeesToken(t *testing.T) (inherited, explicit bool) {
	t.Helper()
	run := func(explicitEnv bool) bool {
		report := filepath.Join(t.TempDir(), "child-env")
		cmd := exec.Command(os.Args[0], "-test.run=^$")
		if explicitEnv {
			cmd.Env = append(os.Environ(), "GO_WANT_OSM_CHILD_ENV_HELPER=1", "TEST_OSM_CHILD_ENV_REPORT="+report)
		} else {
			t.Setenv("GO_WANT_OSM_CHILD_ENV_HELPER", "1")
			t.Setenv("TEST_OSM_CHILD_ENV_REPORT", report)
		}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child tool failed: %v: %s", err, output)
		}
		recorded, err := os.ReadFile(report)
		if err != nil {
			t.Fatalf("child tool left no report: %v", err)
		}
		present, err := strconv.ParseBool(string(recorded))
		if err != nil {
			t.Fatalf("child tool report %q: %v", recorded, err)
		}
		return present
	}
	return run(false), run(true)
}

func TestTakeEnvironmentTokenHidesTheTokenFromChildTools(t *testing.T) {
	t.Setenv(envToken, "synthetic-osm-token")
	token, err := TakeEnvironmentToken()
	if err != nil {
		t.Fatal(err)
	}
	if token != "synthetic-osm-token" {
		t.Fatalf("token = %q, want the environment value", token)
	}
	if _, present := os.LookupEnv(envToken); present {
		t.Fatal("token is still in the process environment")
	}
	if inherited, explicit := childSeesToken(t); inherited || explicit {
		t.Fatalf("child tool saw the token: inherited=%v explicit=%v", inherited, explicit)
	}
}

// Mutation: with the unset disabled, the same child test must see the token.
// This proves the test above cannot pass vacuously.
func TestChildToolTestDetectsAnUnremovedToken(t *testing.T) {
	previous := unsetenv
	unsetenv = func(string) error { return nil }
	t.Cleanup(func() { unsetenv = previous })

	t.Setenv(envToken, "synthetic-osm-token")
	if _, err := TakeEnvironmentToken(); err != nil {
		t.Fatal(err)
	}
	if inherited, explicit := childSeesToken(t); !inherited || !explicit {
		t.Fatalf("child test missed a token left in the environment: inherited=%v explicit=%v", inherited, explicit)
	}
}

func TestTakeEnvironmentTokenWithoutToken(t *testing.T) {
	t.Setenv(envToken, "")
	os.Unsetenv(envToken)
	token, err := TakeEnvironmentToken()
	if err != nil || token != "" {
		t.Fatalf("TakeEnvironmentToken() = %q, %v; want empty, nil", token, err)
	}
}

func TestTakeEnvironmentTokenFailsWhenItCannotRemoveTheToken(t *testing.T) {
	previous := unsetenv
	unsetenv = func(string) error { return errors.New("synthetic unset failure") }
	t.Cleanup(func() { unsetenv = previous })

	t.Setenv(envToken, "synthetic-osm-token")
	token, err := TakeEnvironmentToken()
	if err == nil || token != "" {
		t.Fatalf("TakeEnvironmentToken() = %q, %v; want an error and no token", token, err)
	}
}
