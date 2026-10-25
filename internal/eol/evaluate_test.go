package eol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var fixtureNow = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func fixtureCatalog(t *testing.T) Catalog {
	t.Helper()
	catalog, missing, err := Load(filepath.Join("testdata", "data"), Products)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Fatalf("fixture data lacks %v", missing)
	}
	return catalog
}

type verdict struct {
	Product, Cycle, Version, Reason string
}

func verdicts(hits []Hit) []verdict {
	var out []verdict
	for _, hit := range hits {
		out = append(out, verdict{hit.Product, hit.Cycle, hit.Version, hit.Reason})
	}
	return out
}

func one(product, version string) Pin {
	return Pin{Products: []string{product}, Version: version, Path: "f", Line: 1}
}

func TestEvaluatePolicy(t *testing.T) {
	floor := one("nodejs", "20")
	floor.Floor = true
	codename := Pin{Products: []string{"debian", "ubuntu"}, Version: "bookworm", Codename: true}
	unknownWord := Pin{Products: []string{"debian", "ubuntu"}, Version: "bookworm2", Codename: true}
	pins := []Pin{
		one("nodejs", "20"),      // EOL 2026-04-30: finding
		floor,                    // EOL floor: finding too
		one("go", "1.24.2"),      // EOL 2026-02-10: finding, no trailing noise
		one("rust", "1.98.0"),    // EOL 2026-10-01, inside the 30-day grace: warning
		one("nodejs", "24.22.1"), // newest release; active support ended 2026-10-20
		one("go", "1.26.3"),      // trails 1.26.10 by several patches
		one("go", "1.27.2"),      // one patch behind a 6-day-old release: quiet
		one("go", "1.27"),        // cycle only: never trails
		one("bun", "1.3.9"),      // trails 1.4.4 across a minor: warning
		codename,                 // Debian 12 left active support on 2026-07-11
		one("debian", "11"),      // EOL 2026-08-31, in grace? no: 55 days ago, finding
		one("ubuntu", "24.04"),   // supported
		one("python", "3.10"),    // EOL 2026-10-01: grace
		unknownWord,              // no such codename: not judged
		one("nodejs", "99"),      // unknown cycle: not judged
		one("alpine-linux", "3.19"),
		{Version: "20250101T000000Z", Snapshot: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
		{Version: "20260901T000000Z", Snapshot: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)},
	}
	findings, warnings := Evaluate(pins, fixtureCatalog(t), fixtureNow)
	wantFindings := []verdict{
		{"nodejs", "20", "20", ReasonEndOfLife},
		{"nodejs", "20", "20", ReasonEndOfLife},
		{"go", "1.24", "1.24.2", ReasonEndOfLife},
		{"debian", "11", "11", ReasonEndOfLife},
		{"alpine-linux", "3.19", "3.19", ReasonEndOfLife},
	}
	wantWarnings := []verdict{
		{"rust", "1.98", "1.98.0", ReasonEndOfLifeGrace},
		{"nodejs", "24", "24.22.1", ReasonSupportEnded},
		{"go", "1.26", "1.26.3", ReasonBehindLatest},
		{"bun", "1", "1.3.9", ReasonBehindLatest},
		{"debian", "12", "bookworm", ReasonSupportEnded},
		{"python", "3.10", "3.10", ReasonEndOfLifeGrace},
		{"apt-snapshot", "", "20250101T000000Z", ReasonSnapshotOld},
	}
	if got := verdicts(findings); !reflect.DeepEqual(got, wantFindings) {
		t.Errorf("findings\n got %v\nwant %v", got, wantFindings)
	}
	if got := verdicts(warnings); !reflect.DeepEqual(got, wantWarnings) {
		t.Errorf("warnings\n got %v\nwant %v", got, wantWarnings)
	}
	if !strings.Contains(warnings[0].Detail, "strict scans fail from 2026-10-31") {
		t.Errorf("grace warning does not say when it starts failing: %q", warnings[0].Detail)
	}
}

func TestEvaluateEndOfLifeSoonAndUndatedEndOfLife(t *testing.T) {
	soon := "2026-12-01"
	catalog := Catalog{"python": {Name: "python", Releases: []Release{
		{Name: "3.11", EOLFrom: &soon},
		{Name: "2.7", IsEOL: true},
	}}}
	findings, warnings := Evaluate([]Pin{one("python", "3.11"), one("python", "2.7.18")}, catalog, fixtureNow)
	if got := verdicts(findings); !reflect.DeepEqual(got, []verdict{{"python", "2.7", "2.7.18", ReasonEndOfLife}}) {
		t.Fatalf("findings %v", got)
	}
	if got := verdicts(warnings); !reflect.DeepEqual(got, []verdict{{"python", "3.11", "3.11", ReasonEndOfLifeSoon}}) {
		t.Fatalf("warnings %v", got)
	}
}

func TestMatchPrefersLongestCycleAndCodename(t *testing.T) {
	iron := "Iron"
	product := Product{Releases: []Release{{Name: "1"}, {Name: "1.2"}, {Name: "20", Codename: &iron}}}
	cases := map[string]string{"1.2.9": "1.2", "1.3.0": "1", "v1.2rc1": "1.2", "iron": "20", "12": ""}
	for requested, want := range cases {
		release, ok := match(product, requested)
		if got := release.Name; (want == "" && ok) || got != want {
			t.Errorf("match(%q) = %q, %v; want %q", requested, got, ok, want)
		}
	}
}

func TestLoadReportsMissingAndRejectsInvalidData(t *testing.T) {
	dir := t.TempDir()
	catalog, missing, err := Load(dir, []string{"go"})
	if err != nil || len(catalog) != 0 || !reflect.DeepEqual(missing, []string{"go"}) {
		t.Fatalf("Load on empty dir = %v, %v, %v", catalog, missing, err)
	}
	invalid := map[string]string{
		"not json":       `{`,
		"wrong schema":   `{"schema_version":"2.0.0","result":{"name":"go","releases":[{"name":"1.27"}]}}`,
		"wrong product":  `{"schema_version":"1.2.0","result":{"name":"nodejs","releases":[{"name":"22"}]}}`,
		"no releases":    `{"schema_version":"1.2.0","result":{"name":"go","releases":[]}}`,
		"unnamed":        `{"schema_version":"1.2.0","result":{"name":"go","releases":[{"name":""}]}}`,
		"malformed date": `{"schema_version":"1.2.0","result":{"name":"go","releases":[{"name":"1.27","eolFrom":"soon"}]}}`,
	}
	for name, body := range invalid {
		if err := os.WriteFile(filepath.Join(dir, "go.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Load(dir, []string{"go"}); err == nil {
			t.Errorf("%s: Load accepted invalid data", name)
		}
	}
}

func TestRefreshWritesEveryProductOrNothing(t *testing.T) {
	failing := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		product := strings.Trim(strings.TrimPrefix(r.URL.Path, "/products/"), "/")
		if product == failing {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		raw, err := os.ReadFile(filepath.Join("testdata", "data", product+".json"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	dir := filepath.Join(t.TempDir(), "eol")
	failing = "rust"
	if err := Refresh(context.Background(), server.Client(), server.URL+"/products", dir); err == nil {
		t.Fatal("Refresh succeeded although one product failed")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("a failed refresh wrote %s: %v", dir, err)
	}
	failing = ""
	if err := Refresh(context.Background(), server.Client(), server.URL+"/products", dir); err != nil {
		t.Fatal(err)
	}
	if _, missing, err := Load(dir, Products); err != nil || len(missing) != 0 {
		t.Fatalf("refreshed data incomplete: %v %v", missing, err)
	}
}

func TestRunJudgesATreeEndToEnd(t *testing.T) {
	root := writeTree(t, map[string]string{
		"sdk/go.mod":            "module x\n\ngo 1.24.0\n",
		"images/app/Dockerfile": "ARG BASE=node:22.23.4-bookworm\nFROM ${BASE}\n",
		"README.md":             "FROM node:8\n",
	})
	report, err := Run(root, filepath.Join("testdata", "data"), fixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	if report.Pins != 3 || len(report.Missing) != 0 {
		t.Fatalf("pins=%d missing=%v", report.Pins, report.Missing)
	}
	if got := verdicts(report.Findings); !reflect.DeepEqual(got, []verdict{{"go", "1.24", "1.24.0", ReasonEndOfLife}}) {
		t.Fatalf("findings %v", got)
	}
	if len(report.Warnings) != 2 {
		t.Fatalf("warnings %v", verdicts(report.Warnings))
	}
	missingReport, err := Run(root, t.TempDir(), fixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(missingReport.Missing, []string{"debian", "go", "nodejs", "ubuntu"}) {
		t.Fatalf("missing %v", missingReport.Missing)
	}
}
