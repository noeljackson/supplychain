package cmd

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const githubWorkflow = `name: supplychain

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "17 7 * * 1"
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: supplychain-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  scan:
    uses: noeljackson/supplychain/.github/workflows/scan.yml@ACTION_REF
    with:
      policy: POLICY
`

const giteaWorkflow = `name: supplychain

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "17 7 * * 1"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - name: Check out repository
        uses: https://github.com/actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6
        with:
          persist-credentials: false
      - name: Scan repository
        uses: https://github.com/noeljackson/supplychain@ACTION_REF
        with:
          path: .
          policy: POLICY
`

func cmdInit(_ *Globals, args []string) int {
	if len(args) == 0 || (args[0] != "github" && args[0] != "gitea") {
		fmt.Fprintln(os.Stderr, "usage: supplychain init <github|gitea> --ref=<full commit SHA> [--policy=strict]")
		return 2
	}
	platform := args[0]
	fs := flag.NewFlagSet("init "+platform, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	ref := fs.String("ref", "", "immutable supplychain action commit SHA")
	policy := fs.String("policy", "strict", "auto or strict")
	force := fs.Bool("force", false, "replace an existing workflow")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if len(*ref) != 40 || strings.Trim(*ref, "0123456789abcdef") != "" {
		fmt.Fprintln(os.Stderr, "init "+platform+": --ref must be a lowercase full commit SHA")
		return 2
	}
	if *policy != "auto" && *policy != "strict" {
		fmt.Fprintln(os.Stderr, "init "+platform+": --policy must be auto or strict")
		return 2
	}
	workflow := githubWorkflow
	directory := ".github"
	if platform == "gitea" {
		workflow = giteaWorkflow
		directory = ".gitea"
	}
	path := filepath.Join(directory, "workflows", "supplychain.yml")
	if _, err := os.Stat(path); err == nil && !*force {
		fmt.Fprintln(os.Stderr, "init "+platform+":", path, "already exists; use --force to replace")
		return 1
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(os.Stderr, "init "+platform+":", err)
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "init "+platform+":", err)
		return 1
	}
	contents := strings.ReplaceAll(workflow, "ACTION_REF", *ref)
	contents = strings.ReplaceAll(contents, "POLICY", *policy)
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "init "+platform+":", err)
		return 1
	}
	fmt.Println("installed", path)
	return 0
}
