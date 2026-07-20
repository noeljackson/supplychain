# Recommended Gitea Actions setup

Gitea Actions is mostly compatible with GitHub Actions, but the safest portable
integration is a normal job that calls the composite action through an absolute
URL. Do not copy the GitHub reusable-workflow example verbatim.

## Per-repository source gate

Replace `FULL_COMMIT_SHA` with a reviewed 40-character supplychain commit and
save this as `.gitea/workflows/supplychain.yml`:

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
        uses: https://github.com/noeljackson/supplychain@FULL_COMMIT_SHA
        with:
          path: .
          policy: strict
```

Generate the same workflow from a trusted local installation:

```bash
supplychain init gitea --ref=FULL_COMMIT_SHA
```

Gitea supports absolute action URLs, so the host is explicit even when the
instance's `DEFAULT_ACTIONS_URL` is configured as `self`. The action and
checkout references remain pinned to immutable commits. If runners cannot
reach GitHub, mirror both repositories to a trusted Gitea owner and replace the
URL while preserving and verifying the commit IDs.

Copyable templates are available in
[`examples/gitea/source.yml`](../examples/gitea/source.yml) and
[`examples/gitea/image.yml`](../examples/gitea/image.yml). The centralized
variant is [`examples/gitea/scoped-source.yml`](../examples/gitea/scoped-source.yml).

## Repositories that build an OCI image

Use the same-job pattern as GitHub: scan the source before executing the
Dockerfile, then scan the resulting local image before the job ends.

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - name: Check out repository
        uses: https://github.com/actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6
        with:
          persist-credentials: false
      - name: Gate source before build
        uses: https://github.com/noeljackson/supplychain@FULL_COMMIT_SHA
        with:
          policy: strict
      - name: Build image
        run: docker build --tag app:supplychain-scan .
      - name: Generate SBOM and scan image
        uses: https://github.com/noeljackson/supplychain@FULL_COMMIT_SHA
        with:
          scan-source: false
          image: app:supplychain-scan
          fail-on-severity: high
          only-fixed: false
```

The runner label must select an isolated Linux job environment with a
Docker-compatible socket or daemon. A persistent host socket is a privileged
boundary: do not offer that runner to repositories or contributors you do not
trust. Prefer disposable runner hosts for public fork pull requests.

## Organization-wide and instance-wide enforcement

Gitea 1.27 introduced scoped workflows, which are the cleanest way to apply the
source gate globally. Put the following file in a tightly controlled Gitea
repository such as `security/ci-policy` at
`.gitea/scoped_workflows/supplychain.yml`:

```yaml
name: Supplychain

on: [push, pull_request]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - name: Check out consuming repository
        uses: https://github.com/actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6
        with:
          persist-credentials: false
      - name: Scan consuming repository
        uses: https://github.com/noeljackson/supplychain@FULL_COMMIT_SHA
        with:
          policy: strict
```

Then:

1. Protect the policy repository's default branch and tightly limit who can
   change it. Its workflow content executes in every consuming repository.
2. Register it under organization, user, or site administration settings at
   **Actions → Scoped Workflows**.
3. Mark `Supplychain` required and configure the status pattern shown by Gitea,
   normally `security/ci-policy: Supplychain / *`.
4. Ensure each consuming target branch has a branch protection rule; scoped
   required checks are enforced only on protected branches.

Scoped workflows currently do not support `schedule`. Keep the per-repository
weekly workflow when time-based rescans are required, or dispatch scheduled
scans centrally through a separate trusted automation path.

## Gitea-specific security settings

At the organization and repository levels under **Actions → General**:

1. Set default job-token permissions to **Restricted** and keep the workflow's
   explicit `permissions: contents: read`.
2. Clamp maximum permissions so repository workflows cannot request writes they
   do not need.
3. Do not grant cross-repository access to the scan job. Public, SHA-pinned
   action repositories are read-only and do not need it.
4. Require approval before running fork pull requests on self-hosted runners.
5. Register runners only at a scope whose repositories are trusted to execute
   on them, and always use isolated job containers.
6. Protect `main` and require the supplychain status before merge.

Gitea pull-request workflows scan the pull-request head rather than a synthetic
merge commit. Keep normal integration tests as a separate required check when
base-branch interaction matters.

## Compatibility notes

- Gitea accepts absolute action URLs; GitHub does not.
- The `contents: read` permission works on current Gitea and maps to read access
  for code and releases.
- Some older Gitea versions ignore workflow features such as concurrency or job
  timeouts. The scanner has its own bounded subprocess timeouts, but the runner
  should also enforce an outer job limit.
- Gitea does not currently surface GitHub-style problem matcher annotations, so
  read the job log for the complete zizmor, Gitleaks, OSV, Syft, and Grype
  output.
- Publishing images is a separate privileged workflow. Current Gitea versions
  may require an explicitly scoped package token; do not add it to this
  read-only pull-request scan.

Official Gitea references:

- [Gitea Actions overview](https://docs.gitea.com/usage/actions/overview)
- [Differences from GitHub Actions](https://docs.gitea.com/usage/actions/comparison)
- [Job-token permissions](https://docs.gitea.com/usage/actions/token-permissions)
- [Scoped workflows](https://docs.gitea.com/usage/actions/scoped-workflows)
- [Gitea Actions security FAQ](https://docs.gitea.com/usage/actions/faq#how-to-avoid-being-hacked)
