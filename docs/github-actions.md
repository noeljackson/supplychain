# Recommended GitHub Actions setup

This is the default setup we recommend for every GitHub repository. It runs a
strict, read-only source gate on pull requests, the default branch, a weekly
schedule, and manual dispatch. It does not pass secrets to the scanner or run
project install scripts.

For Gitea, use the separate [Gitea Actions guide](gitea-actions.md); its
absolute action URLs and global scoped-workflow model are intentionally
different.

## Source-only repositories

Resolve and review a `supplychain` commit, then replace `FULL_COMMIT_SHA` with
its complete 40-character lowercase SHA. Do not use `main`, a branch name, or a
floating version tag.

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
      # Optional: only for a tracked policy with narrowly reviewed exceptions.
      # gitleaks-config: .gitleaks.toml
```

Save this as `.github/workflows/supplychain.yml`, or generate it from a trusted
local installation:

```bash
supplychain init github --ref=FULL_COMMIT_SHA
```

Copyable templates are available in
[`examples/github/source.yml`](../examples/github/source.yml) and
[`examples/github/image.yml`](../examples/github/image.yml).

The generator rejects mutable references. The called workflow has a 20-minute
timeout, checks out the caller without persisted credentials, checks out its
own implementation at the exact called-workflow commit, verifies Go module
checksums, and installs hash-pinned scanners before inspecting the repository.

The weekly run matters even when the dependency graph has not changed: newly
published advisories can make an already-accepted version unsafe. The embedded
malware-indicator snapshot remains tied to the pinned action commit, so advance
that pin through reviewed pull requests on a regular cadence.

## Repositories that build an OCI image

Run the source gate before executing the repository's Dockerfile. Build and scan
the image in the same job because a local Docker image does not cross GitHub
Actions job boundaries.

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
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - name: Check out repository
        uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6
        with:
          persist-credentials: false

      - name: Gate source before build
        uses: noeljackson/supplychain@FULL_COMMIT_SHA
        with:
          policy: strict

      - name: Build image
        run: docker build --tag app:supplychain-scan .

      - name: Generate SBOM and scan image
        uses: noeljackson/supplychain@FULL_COMMIT_SHA
        with:
          scan-source: false
          image: app:supplychain-scan
          fail-on-severity: high
          only-fixed: false
```

The image step inventories the exact image with Syft, validates the SPDX JSON,
then scans that SBOM with Grype. Keep `only-fixed: false`: an unfixed critical or
high vulnerability is still relevant risk and should not silently disappear.

If a Dockerfile needs private registries or other build secrets, do not expose
them to `pull_request` jobs from forks. Put privileged build and publication in
a separate trusted workflow and keep this pull-request gate read-only.

## Monorepositories

The reusable workflow scans the repository root. A root scan finds manifests
throughout the repository, but Bun's registry signature, release-age, and
baseline verification is activated for a `bun.lock` at the target path. Add one
composite action step for each nested Bun project that needs that verification:

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6
        with:
          persist-credentials: false
      - name: Scan repository
        uses: noeljackson/supplychain@FULL_COMMIT_SHA
        with:
          policy: strict
      - name: Verify UI Bun dependencies
        uses: noeljackson/supplychain@FULL_COMMIT_SHA
        with:
          path: ui
          policy: strict
          baseline: .supplychain/bun-baseline.json
```

## Repository settings

Pair the workflow with these repository settings:

1. Set the default `GITHUB_TOKEN` permission to read-only. Keep the workflow's
   explicit `permissions: contents: read` even when the organization default is
   already restrictive.
2. Protect `main` and require the successful `scan` check before merge. Apply
   the rule to administrators too if bypasses are not part of your incident
   procedure.
3. Restrict which actions may run. Allow GitHub-owned actions and this action;
   continue pinning every third-party `uses:` entry to a full commit SHA.
4. Require approval for first-time or all outside collaborators before forked
   pull-request workflows run.
5. Let Dependabot or Renovate propose action-SHA updates, but review the source
   diff before merging the new pin.
6. Prefer GitHub-hosted runners for untrusted pull requests. Do not expose a
   long-lived self-hosted runner to arbitrary fork code; use disposable,
   isolated runners if self-hosting is required.

## Trust boundaries

The pull-request scanner deliberately needs only `contents: read`. Do not add:

- `pull_request_target` while checking out or executing pull-request code;
- `secrets: inherit` or repository credentials for an untrusted scan;
- broad `write-all`, package, deployment, OIDC, or attestation permissions;
- project dependency installation before the source gate;
- mutable action references such as `@main` or `@v1`.

`pull_request_target` runs in the base repository's privileged context. It is
appropriate only for carefully designed metadata automation that never executes
untrusted pull-request content. It is not the right trigger for this scanner.

## Releases and attestations

Keep publication in a separate tag or protected-branch workflow. That job may
need narrowly scoped write permissions such as `contents`, `packages`, OIDC,
and artifact attestation, but the pull-request scan does not. Generate an SBOM
for the final artifact or image, attest the thing actually published, and pin
the attestation action to a full commit SHA as well.

GitHub's own guidance explains the underlying controls:

- [Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use?learn=getting_started&learnProduct=actions)
- [Using `GITHUB_TOKEN`](https://docs.github.com/en/actions/tutorials/authenticate-with-github_token?apiVersion=2022-11-28)
- [Secure use of `pull_request_target`](https://docs.github.com/en/enterprise-server%403.17/actions/reference/security/securely-using-pull_request_target)
- [Workflow concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)
- [Artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
