package eol

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

type found struct {
	Products string
	Version  string
	Where    string
	Floor    bool
	Codename bool
}

func summarize(pins []Pin) []found {
	var out []found
	for _, pin := range pins {
		out = append(out, found{
			Products: strings.Join(pin.Products, "|"), Version: pin.Version,
			Where: pin.Path + ":" + strconv.Itoa(pin.Line), Floor: pin.Floor, Codename: pin.Codename,
		})
	}
	return out
}

func discover(t *testing.T, files map[string]string) []found {
	t.Helper()
	pins, err := Discover(writeTree(t, files))
	if err != nil {
		t.Fatal(err)
	}
	return summarize(pins)
}

func TestGoModuleAndWorkspaceDirectives(t *testing.T) {
	got := discover(t, map[string]string{
		"libs/sdk/go.mod": "module example.com/sdk\n\ngo 1.24.2\n\ntoolchain go1.25.1\n",
		"go.work":         "go 1.27.3 // workspace\n\nuse ./libs/sdk\n",
	})
	want := []found{
		{Products: "go", Version: "1.27.3", Where: "go.work:1"},
		{Products: "go", Version: "1.24.2", Where: "libs/sdk/go.mod:3"},
		{Products: "go", Version: "1.25.1", Where: "libs/sdk/go.mod:5"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
}

func TestPackageJSONEnginesAndPackageManager(t *testing.T) {
	got := discover(t, map[string]string{
		"package.json": `{
  "name": "root",
  "packageManager": "bun@1.3.9+sha512.abc",
  "engines": {
    "node": ">=20 <23",
    "bun": "^1.1.0"
  }
}
`,
		"web/package.json":    `{"packageManager": "pnpm@9.1.0", "engines": {"node": "lts/*"}}`,
		"broken/package.json": `{`,
	})
	want := []found{
		{Products: "bun", Version: "1.3.9", Where: "package.json:3"},
		{Products: "nodejs", Version: "20", Where: "package.json:5", Floor: true},
		{Products: "bun", Version: "1.1.0", Where: "package.json:6", Floor: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
}

func TestVersionFilesToolVersionsAndRustToolchain(t *testing.T) {
	got := discover(t, map[string]string{
		".nvmrc":                    "v18.19.0\n",
		"site/.node-version":        "lts/iron\n",
		"alias/.nvmrc":              "node\n",
		".python-version":           "# pinned\n3.9.18\n",
		".tool-versions":            "golang 1.21.5\nnodejs 22.3.0\nterraform 1.8.0\nrust stable\n",
		"rust-toolchain.toml":       "[toolchain]\nchannel = \"1.98.0\"\n",
		"old/rust-toolchain":        "1.80.1\n",
		"night/rust-toolchain.toml": "[toolchain]\nchannel = \"nightly-2026-01-01\"\n",
	})
	want := []found{
		{Products: "nodejs", Version: "18.19.0", Where: ".nvmrc:1"},
		{Products: "python", Version: "3.9.18", Where: ".python-version:2"},
		{Products: "go", Version: "1.21.5", Where: ".tool-versions:1"},
		{Products: "nodejs", Version: "22.3.0", Where: ".tool-versions:2"},
		{Products: "rust", Version: "1.80.1", Where: "old/rust-toolchain:1"},
		{Products: "rust", Version: "1.98.0", Where: "rust-toolchain.toml:2"},
		{Products: "nodejs", Version: "iron", Where: "site/.node-version:1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
}

func TestDockerfilesAnywhereWithStagesArgsAndVariants(t *testing.T) {
	got := discover(t, map[string]string{
		"deploy/docker/api.Dockerfile": `# syntax=docker/dockerfile:1
ARG NODE_IMAGE=registry.example/mirror/library/node:20.11.1-bookworm-slim@sha256:abc
ARG UNSET
FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS build
FROM build AS test
FROM ${UNSET} AS skipped
FROM scratch
FROM \
  golang:${GO:-1.22}-alpine3.18 AS tools
FROM gcr.io/distroless/nodejs18-debian11:nonroot
`,
		"images/base/Dockerfile":        "FROM ubuntu:jammy\nRUN echo https://snapshot.ubuntu.com/ubuntu/20240101T000000Z/ ok\n",
		"tools/Containerfile.release":   "FROM docker.io/oven/bun:1.1.38-alpine\n",
		"tools/Dockerfile.dockerignore": "FROM node:12\n",
		"node_modules/x/Dockerfile":     "FROM node:8\n",
		"testdata/Dockerfile":           "FROM node:8\n",
		"py/Dockerfile":                 "FROM python:latest\nFROM python\nFROM debian:12.4\n",
	})
	want := []found{
		{Products: "nodejs", Version: "20.11.1", Where: "deploy/docker/api.Dockerfile:4"},
		{Products: "debian|ubuntu", Version: "bookworm", Where: "deploy/docker/api.Dockerfile:4", Codename: true},
		{Products: "go", Version: "1.22", Where: "deploy/docker/api.Dockerfile:8"},
		{Products: "alpine-linux", Version: "3.18", Where: "deploy/docker/api.Dockerfile:8"},
		{Products: "debian", Version: "11", Where: "deploy/docker/api.Dockerfile:10"},
		{Products: "nodejs", Version: "18", Where: "deploy/docker/api.Dockerfile:10"},
		{Products: "ubuntu", Version: "jammy", Where: "images/base/Dockerfile:1", Codename: true},
		{Products: "", Version: "20240101T000000Z", Where: "images/base/Dockerfile:2"},
		{Products: "debian", Version: "12.4", Where: "py/Dockerfile:3"},
		{Products: "bun", Version: "1.1.38", Where: "tools/Containerfile.release:1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
}

func TestWorkflowsAndActionMetadata(t *testing.T) {
	got := discover(t, map[string]string{
		".github/workflows/ci.yml": `jobs:
  test:
    runs-on: ubuntu-latest
    container: node:16-bullseye
    services:
      db:
        image: "python:3.8-slim" # legacy
    steps:
      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'
      - uses: actions/setup-node@v4
        with:
          node-version: [18, 20.x]
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python }}
      - uses: docker://alpine:3.17
`,
		".forgejo/workflows/bun.yaml": "      - with:\n          bun-version: '1.0.0'\n",
		"actions/build/action.yml":    "runs:\n  using: 'node16'\n  main: index.js\n",
		"actions/img/action.yaml":     "runs:\n  using: docker\n  image: Dockerfile\n",
		"actions/remote/action.yml":   "runs:\n  using: docker\n  image: docker://debian:buster\n",
		"docs/workflows/ci.yml":       "node-version: 10\n",
		"k8s/job.yaml":                "spec:\n  containers:\n    - name: x\n      image: docker.io/library/python:3.13.9-alpine3.22@sha256:abc\n      imagePullPolicy: Always\n",
	})
	want := []found{
		{Products: "bun", Version: "1.0.0", Where: ".forgejo/workflows/bun.yaml:2"},
		{Products: "nodejs", Version: "16", Where: ".github/workflows/ci.yml:4"},
		{Products: "debian|ubuntu", Version: "bullseye", Where: ".github/workflows/ci.yml:4", Codename: true},
		{Products: "python", Version: "3.8", Where: ".github/workflows/ci.yml:7"},
		{Products: "go", Version: "1.21", Where: ".github/workflows/ci.yml:11"},
		{Products: "nodejs", Version: "18", Where: ".github/workflows/ci.yml:14"},
		{Products: "nodejs", Version: "20", Where: ".github/workflows/ci.yml:14"},
		{Products: "alpine-linux", Version: "3.17", Where: ".github/workflows/ci.yml:18"},
		{Products: "nodejs", Version: "16", Where: "actions/build/action.yml:2"},
		{Products: "debian", Version: "buster", Where: "actions/remote/action.yml:3", Codename: true},
		{Products: "python", Version: "3.13.9", Where: "k8s/job.yaml:4"},
		{Products: "alpine-linux", Version: "3.22", Where: "k8s/job.yaml:4"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
}

func TestAptSourcesSnapshots(t *testing.T) {
	pins, err := Discover(writeTree(t, map[string]string{
		"images/ubuntu.sources": "Types: deb\nURIs: https://snapshot.ubuntu.com/ubuntu/20260803T000000Z/\n",
		"etc/sources.list":      "deb https://snapshot.debian.org/archive/debian/20251208T000000Z/ bookworm main\n",
		"README.md":             "https://snapshot.debian.org/archive/debian/20200101T000000Z/\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != 2 {
		t.Fatalf("got %d pins, want 2: %#v", len(pins), pins)
	}
	if pins[0].Path != "etc/sources.list" || !pins[0].Snapshot.Equal(time.Date(2025, 12, 8, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("unexpected first snapshot pin %#v", pins[0])
	}
}

func TestExpandArguments(t *testing.T) {
	args := map[string]string{"SET": "node:22", "EMPTY": ""}
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"$SET", "node:22", true},
		{"${SET}", "node:22", true},
		{"${EMPTY:-node:20}", "node:20", true},
		{"${EMPTY-node:20}", "", false},
		{"${MISSING-node:18}", "node:18", true},
		{"${SET:+python:3.12}", "python:3.12", true},
		{"${MISSING}", "", false},
		{"base-${MISSING}", "base-", false},
	}
	for _, c := range cases {
		got, ok := expand(c.in, args)
		if got != c.want || ok != c.ok {
			t.Errorf("expand(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}
