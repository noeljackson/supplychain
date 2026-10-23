package cmd

import (
	"flag"
	"io"
	"reflect"
	"testing"
)

func TestFlagsAfterImageTarget(t *testing.T) {
	fs := flag.NewFlagSet("image", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	severity := fs.String("fail-on", "high", "")
	sbom := fs.String("sbom", "default.json", "")
	fixed := fs.Bool("only-fixed", false, "")
	if err := parseFlags(fs, []string{"app:release", "--fail-on=critical", "--sbom", "report.json", "--only-fixed"}); err != nil {
		t.Fatal(err)
	}
	if *severity != "critical" || *sbom != "report.json" || !*fixed || !reflect.DeepEqual(fs.Args(), []string{"app:release"}) {
		t.Fatalf("flags or target were dropped: severity=%s sbom=%s fixed=%v args=%v", *severity, *sbom, *fixed, fs.Args())
	}
}

func TestLiteralEndMarkerAndMissingFlagValue(t *testing.T) {
	fs := flag.NewFlagSet("image", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.String("sbom", "", "")
	if err := parseFlags(fs, []string{"--", "--help"}); err != nil || !reflect.DeepEqual(fs.Args(), []string{"--help"}) {
		t.Fatalf("literal target was parsed as an option: %v, %v", fs.Args(), err)
	}
	if err := parseFlags(fs, []string{"app:release", "--sbom"}); err == nil {
		t.Fatal("missing flag value was accepted")
	}
}

func TestScanHelpDoesNotScanAPath(t *testing.T) {
	if exit := cmdScan(&Globals{}, []string{"--help"}); exit != 0 {
		t.Fatalf("scan --help exit = %d, want 0", exit)
	}
}

func TestGlobalFlagsRespectLiteralEndMarker(t *testing.T) {
	g := &Globals{}
	got := parseGlobalFlags(g, []string{"scan", "--", "--json"})
	if g.JSON || !reflect.DeepEqual(got, []string{"scan", "--", "--json"}) {
		t.Fatalf("literal path was consumed as a global flag: %v, json=%v", got, g.JSON)
	}
}
