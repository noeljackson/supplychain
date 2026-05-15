package osm

import (
	"reflect"
	"testing"
)

func TestParseVersionInfo_ConcretePins(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"1.2.3", []string{"1.2.3"}},
		{"1.2.3-beta.1", []string{"1.2.3-beta.1"}},
		{"1.2.3, 1.2.4", []string{"1.2.3", "1.2.4"}},
		{"1.2.3,1.2.4", []string{"1.2.3", "1.2.4"}},
		{"  1.2.3 ;  1.2.4  ", []string{"1.2.3", "1.2.4"}},
		{"1.2.3 1.2.3 1.2.4", []string{"1.2.3", "1.2.4"}}, // dedup
	}
	for _, c := range cases {
		got := parseVersionInfo(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseVersionInfo(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseVersionInfo_RangesRejected(t *testing.T) {
	rejects := []string{
		"^1.2.3",
		"~1.2.3",
		">=1.0.0, <2.0.0",
		">1.0",
		"*",
		"",
		"1.x",
		"latest",
		"1.2",     // not full semver
		"1.2.3.4", // not semver
	}
	for _, in := range rejects {
		if got := parseVersionInfo(in); got != nil {
			t.Errorf("parseVersionInfo(%q) = %v, want nil (range or invalid)", in, got)
		}
	}
}
