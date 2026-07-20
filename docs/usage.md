# Using supplychain

The normal workflow is simple: run the strict GitHub Action on every pull
request, use `supplychain ci --policy=strict` for local parity, and use
`supplychain image` for an OCI image after it has been built.

See [Recommended GitHub Actions setup](github-actions.md) for complete workflow
files and repository settings. Gitea users should start with the
[Gitea Actions guide](gitea-actions.md).

## Install locally

Build from a reviewed checkout:

```bash
git clone https://github.com/noeljackson/supplychain.git
cd supplychain
git checkout FULL_COMMIT_SHA
make install
supplychain update
supplychain doctor
```

`supplychain update` refreshes public indicator data and installs OSV Scanner.
An OpenSourceMalware token is optional; OSV Scanner does not need an API key.

A strict local source scan also requires `gitleaks` and `zizmor`. Image scans
require `syft` and `grype`. The GitHub Action installs immutable, hash-verified
versions automatically. On Linux, a reviewed checkout can install the same
pinned helpers locally:

```bash
SUPPLYCHAIN_BIN_DIR="$HOME/.local/bin" \
  ./scripts/install-ci-tools --source-tools --image-tools
```

Make sure `$HOME/.local/bin` is on `PATH`. On other operating systems, install
those helper programs with the system package manager and then run
`supplychain doctor` plus a strict scan.

## Everyday commands

```bash
# The local equivalent of the required source gate
supplychain ci --policy=strict .

# Opt in to one reviewed, tracked repository policy
supplychain ci --policy=strict --gitleaks-config=.gitleaks.toml .

# General repository/dependency/IOC scan
supplychain scan .

# Machine-readable output
supplychain --json scan .

# Redacted secret scan of tracked and non-ignored untracked files
supplychain secrets .

# Offline GitHub and Gitea Actions audit
supplychain workflows .

# Generate an SPDX SBOM and fail on high/critical image findings
supplychain image --sbom=app.spdx.json --fail-on=high app:test

# Scan every Git repository under a source directory
supplychain scan-all "$HOME/src"

# Check the installation and refresh public data/tools
supplychain doctor
supplychain update
```

Generate a pinned caller workflow for either forge:

```bash
supplychain init github --ref=FULL_COMMIT_SHA
supplychain init gitea --ref=FULL_COMMIT_SHA
```

Commands return nonzero when their enforced policy fails, so they can be used
directly in scripts and CI. `--quiet` suppresses clean output, and `--json`
provides structured scan results.

## Strict and auto policies

Use `strict` in CI. `auto` is useful only as a lower-friction exploratory scan.

| Check | `auto` | `strict` |
| --- | --- | --- |
| Known malicious packages and repository indicators | enforced | enforced |
| Dependency advisories and lockfile drift | reported | enforced |
| OSV Scanner availability and successful execution | best effort | required |
| GitHub Actions audit with zizmor | skipped | enforced |
| Redacted secret scan with Gitleaks | skipped | enforced |
| Bun registry verification when target has `bun.lock` | enforced | enforced |

CI uses the malware-indicator snapshot embedded in the action's pinned commit
and does not mutate it during a run. Scheduled scans can still find newly
published advisories; advance the pinned action SHA through review to pick up a
new embedded malware-indicator snapshot and scanner versions.

## Bun projects

For a Bun project, strict CI verifies that lock entries come from the npm
registry, their SHA-512 integrity matches npm metadata, registry signatures are
valid, and releases are at least seven days old by default.

Create a reviewed baseline after a dependency update has passed those checks:

```bash
supplychain verify-bun \
  --minimum-age-days=30 \
  --write-baseline \
  --baseline=.supplychain/bun-baseline.json \
  .

git add bun.lock .supplychain/bun-baseline.json
```

The baseline detects later maintainer-set changes, integrity drift, unexpected
packages, and loss of advertised npm provenance. Review both the lockfile and
baseline diff in the same pull request. In a monorepository, run the action or
command once per directory containing a `bun.lock`.

## Secret findings

Gitleaks runs with redaction and analytics disabled. It scans files visible to
Git: tracked files plus untracked files that are not ignored. Generated
dependencies, ignored build output, and symlink targets are excluded.

If a finding is a real credential, rotate or revoke it before doing anything
else, then remove it from the current tree and relevant history. For a reviewed
synthetic test value, an inline `gitleaks:allow` comment is the smallest
exception mechanism.

Repository-owned Gitleaks configuration and ignore files are ignored by
default. If several public values need narrow rule/path/value-shape exceptions,
select a reviewed config explicitly:

```bash
supplychain secrets --gitleaks-config=.gitleaks.toml .
supplychain ci --policy=strict --gitleaks-config=.gitleaks.toml .
```

The selected file must be a regular, tracked file inside the scan target. It is
not scanned as source, and environment-provided Gitleaks configuration remains
scrubbed. `.gitleaksignore` is never honored. Treat changes to the selected
policy like workflow changes: require security-owner review and keep every
allowlist narrower than the finding it documents.

## Image findings

`supplychain image` makes Syft generate the SPDX inventory and makes Grype scan
that exact document. The default threshold is `high`.

```bash
supplychain image \
  --sbom=dist/app.spdx.json \
  --fail-on=high \
  app:test
```

Avoid `--only-fixed` as a default. It limits failures to vulnerabilities with a
published fix and can therefore hide known high-impact exposure. Use it only
for an explicitly documented temporary policy, not to make a red build green.

## Optional hooks and audits

```bash
# Install a local pre-commit hook that scans when manifests/lockfiles change
supplychain install-hook pre-commit

# Show the Claude SessionStart configuration without editing it
supplychain install-hook claude-sessionstart

# Sweep home-directory persistence artifacts, histories, and source repos
supplychain audit-system --git-root="$HOME/src"
```

The pre-commit hook is a convenience, not the enforcement boundary. The
required GitHub check is authoritative because local hooks can be bypassed.

## Network and credentials

Local updates and registry-backed checks need outbound HTTPS to GitHub release
assets, npm, OSV, and the configured indicator source. If a download times out
on a machine with an application firewall, approve the exact tool/domain and
retry; do not disable checksum or signature checks.

`SUPPLYCHAIN_OSM_TOKEN` optionally enriches npm malware indicators from
OpenSourceMalware. Do not add it to GitHub Actions just for the standard strict
gate: pinned CI is intentionally deterministic and does not require that token.
