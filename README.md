# supplychain

`supplychain` is a read-only repository and dependency scanner. It detects
known malicious packages, lockfile drift, install hooks, persistence artifacts,
maintainer changes, fresh npm releases, and strict Bun registry metadata without
executing code from the repository being inspected.

## GitHub Action

Pin the action to a full commit SHA:

```yaml
name: supplychain

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    uses: noeljackson/supplychain/.github/workflows/scan.yml@FULL_COMMIT_SHA
    with:
      policy: strict
```

The reusable workflow checks out its own source at the exact called-workflow
commit, builds it with Go module checksum verification, and scans the caller
checkout without running package-manager or project scripts.

To add the caller workflow to a repository:

```bash
supplychain init github --ref=FULL_COMMIT_SHA
```

The root composite action is also available inside an existing job:

```yaml
- uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6
  with:
    persist-credentials: false
- uses: noeljackson/supplychain@FULL_COMMIT_SHA
  with:
    policy: strict
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
```

Normal workstation scans may refresh public IOC data. CI always uses the IOC
snapshot embedded in the pinned scanner source and does not download helper
binaries.
