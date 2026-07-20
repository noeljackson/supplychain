# supplychain

`supplychain` is a read-only repository and dependency scanner. It detects
known malicious packages, lockfile drift, install hooks, persistence artifacts,
maintainer changes, fresh npm releases, and strict Bun registry metadata without
executing code from the repository being inspected.

## Start here

- [Recommended GitHub Actions setup](docs/github-actions.md) — the complete
  source-only, container-image, monorepo, permissions, and repository-settings
  patterns.
- [Recommended Gitea Actions setup](docs/gitea-actions.md) — portable
  per-repository workflows plus organization/instance-wide scoped enforcement.
- [Usage guide](docs/usage.md) — local installation, commands, Bun baselines,
  secret findings, image scans, and troubleshooting.

## GitHub Action

Pin the action to a full commit SHA:

```yaml
name: supplychain

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
    uses: noeljackson/supplychain/.github/workflows/scan.yml@FULL_COMMIT_SHA
    with:
      policy: strict
```

The reusable workflow checks out its own source at the exact called-workflow
commit, builds it with Go module checksum verification, and scans the caller
checkout without running package-manager or project scripts. Pair it with the
repository controls in the [GitHub Actions guide](docs/github-actions.md).

To add the caller workflow to a repository:

```bash
supplychain init github --ref=FULL_COMMIT_SHA
```

Gitea uses the composite action through an absolute, SHA-pinned URL. See the
[Gitea guide](docs/gitea-actions.md), or generate the per-repository workflow:

```bash
supplychain init gitea --ref=FULL_COMMIT_SHA
```

The root composite action is also available inside an existing job:

```yaml
- uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6
  with:
    persist-credentials: false
- uses: noeljackson/supplychain@FULL_COMMIT_SHA
  with:
    policy: strict
    image: app:test
    fail-on-severity: high
```

Strict scans also run zizmor offline against GitHub and Gitea Actions definitions,
failing on medium-or-higher, medium-confidence findings and workflow schema
errors without exposing a GitHub token to the analyzer. They also run Gitleaks
with redaction and analytics disabled so checked-out repository secrets fail
closed without printing secret values. The scanner stages a temporary hard-link
view of tracked and non-ignored untracked files, so generated dependencies and
build artifacts are excluded without copying secret-bearing source files or
following repository symlinks. Repository-controlled Gitleaks config and ignore
files cannot weaken the global policy; reviewed inline `gitleaks:allow` comments
are the explicit exception mechanism.

When `image` is set, the action creates an SPDX JSON SBOM with Syft and scans
that exact document with Grype. The `sbom` action output is suitable for later
artifact upload or attestation. Gitleaks, Syft, Grype, and OSV Scanner are
installed from cooldown-aged, immutable releases whose expected SHA-256 hashes
live in this repository. Strict source scans fail if OSV Scanner is absent or
fails; image scans require a fresh, hash-valid Grype database and a successful
update check.

The reusable workflow is source-only because reusable jobs cannot see an image
built in a caller job. Use the composite action in the same job, after
`docker build`, when image scanning is required. If an earlier step or job has
already run the source gate, set `scan-source: false` on the post-build action
to install and run only Syft and Grype.

```yaml
- uses: noeljackson/supplychain@FULL_COMMIT_SHA
  with:
    scan-source: false
    image: app:test
    fail-on-severity: high
```

Local image scan with already-installed Syft and Grype:

```bash
supplychain image --sbom=app.spdx.json --fail-on=high app:test
```

## Bun verification

```bash
supplychain verify-bun --minimum-age-days=7 .
supplychain verify-bun --minimum-age-days=30 \
  --write-baseline --baseline=.supplychain/bun-baseline.json .
```

The verifier requires registry-only lock entries, SHA-512 integrity matching
the npm packument, a valid npm ECDSA registry signature, and a publication
timestamp older than the configured window. A reviewed baseline also detects
maintainer changes, integrity drift, new packages, and loss of advertised npm
provenance.

## Local use

```bash
make test
make install
supplychain ci --policy=strict .
supplychain secrets .
```

For all commands and local helper requirements, see the
[usage guide](docs/usage.md).

Normal workstation scans may refresh public IOC data. CI always uses the IOC
snapshot embedded in the pinned scanner source. The global action downloads
only its pinned, hash-checked OSV/zizmor/Syft/Grype helper versions.
