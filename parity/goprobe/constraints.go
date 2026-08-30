package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// readMatrix loads the shared spec/version matrix. Keeping the inputs in one
// tracked file means the Go and Rust probes cannot drift apart on coverage.
func readMatrix(path string) (specs, versions []string, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	section := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case line == "[specs]":
			section = "specs"
			continue
		case line == "[versions]":
			section = "versions"
			continue
		case len(line) < 2 || !strings.HasPrefix(line, "'") || !strings.HasSuffix(line, "'"):
			continue
		}
		value := line[1 : len(line)-1]
		switch section {
		case "specs":
			specs = append(specs, value)
		case "versions":
			versions = append(versions, value)
		}
	}
	return specs, versions, scanner.Err()
}

// probeConstraints dumps the full constraint x version truth table. Masterminds
// constraint semantics are npm-flavoured and differ from Cargo's VersionReq --
// a bare "1.2.3" is exact equality here, not a caret range -- so the Rust port
// is validated against this table rather than an assumption.
func probeConstraints() error {
	specs, versions, err := readMatrix("parity/semver-matrix.txt")
	if err != nil {
		return err
	}
	for _, spec := range specs {
		constraint, err := semver.NewConstraint(spec)
		if err != nil {
			fmt.Printf("CONSTRAINT\t%q\tPARSE_ERR\n", spec)
			continue
		}
		for _, raw := range versions {
			version, err := semver.NewVersion(raw)
			if err != nil {
				continue
			}
			fmt.Printf("CONSTRAINT\t%q\t%s\t%t\n", spec, raw, constraint.Check(version))
		}
	}
	return nil
}
