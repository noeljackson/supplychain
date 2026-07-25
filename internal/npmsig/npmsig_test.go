package npmsig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func init() {
	if os.Getenv("GO_WANT_NPM_TIMEOUT_HELPER") != "1" ||
		filepath.Base(os.Args[0]) != "npm" {
		return
	}
	time.Sleep(time.Second)
	os.Exit(0)
}

func TestParse_Empty(t *testing.T) {
	hits, err := parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if hits != nil {
		t.Errorf("expected nil, got %v", hits)
	}
}

func TestParse_NothingWrong(t *testing.T) {
	in := []byte(`{"invalid":[],"missing":[]}`)
	hits, err := parse(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Errorf("expected no hits, got %v", hits)
	}
}

func TestParse_InvalidAndMissing(t *testing.T) {
	in := []byte(`{
	  "invalid": [
	    {"name":"evil-pkg","version":"1.0.0","resolved":"https://r.example/evil-pkg-1.0.0.tgz"}
	  ],
	  "missing": [
	    {"name":"another","version":"2.0.0","resolved":"https://r.example/another-2.0.0.tgz"}
	  ]
	}`)
	hits, err := parse(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 {
		t.Fatalf("len(hits)=%d, want 2: %+v", len(hits), hits)
	}
	want := map[string]string{"evil-pkg": "invalid", "another": "missing"}
	for _, h := range hits {
		if want[h.Name] != h.Reason {
			t.Errorf("%s: reason=%q, want %q", h.Name, h.Reason, want[h.Name])
		}
	}
}

func TestParseRejectsNonJSON(t *testing.T) {
	if _, err := parse([]byte("some text not actually json")); err == nil {
		t.Fatal("expected malformed JSON error")
	}
}

func TestRunReportsTimeoutAsOperationalFailure(t *testing.T) {
	binDir := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(executable, filepath.Join(binDir, "npm")); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "package-lock.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("GO_WANT_NPM_TIMEOUT_HELPER", "1")
	previousTimeout := auditTimeout
	auditTimeout = 20 * time.Millisecond
	t.Cleanup(func() { auditTimeout = previousTimeout })

	if _, err := Run(target); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected explicit timeout failure, got %v", err)
	}
}

func FuzzParseExternalToolOutput(f *testing.F) {
	f.Add([]byte(`{"invalid":[],"missing":[]}`))
	f.Add([]byte(`{"invalid":[{"name":"x","version":"1.0.0"}]}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 1024*1024 {
			t.Skip()
		}
		_, _ = parse(body)
	})
}
