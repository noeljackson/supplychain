# Runtime, toolchain and base-image end of life

A dependency lockfile says nothing about the runtime that executes it. A
repository can have clean lockfiles and still build on Node.js 20, Go 1.24 or
Debian 10, all past end of life and no longer receiving security fixes. The
`runtime_eol` check finds those pins and judges them against
[endoflife.date](https://endoflife.date) data.

## What it reads

In a Git worktree it reads only tracked files; elsewhere it walks the tree.
`node_modules`, `vendor`, `target`, `testdata` and `.git` directories and
symbolic links are skipped.

| File | Pin |
| --- | --- |
| `go.mod`, `go.work` | `go` and `toolchain` directives |
| `package.json` | `engines.node`, `engines.bun` (lower bound), `packageManager: bun@…` |
| `.nvmrc`, `.node-version`, `.python-version`, `.bun-version` | the requested version, including `lts/<codename>` |
| `.tool-versions` | `nodejs`, `node`, `golang`, `go`, `python`, `bun`, `rust` |
| `rust-toolchain.toml`, `rust-toolchain` | a numbered `channel`; `stable`, `beta` and `nightly` float and are skipped |
| `Dockerfile`, `Containerfile`, `*.Dockerfile`, `Dockerfile.*` anywhere | every `FROM`, including later stages, with `ARG` defaults declared before the first `FROM` resolved |
| Workflows under `.github`, `.gitea` and `.forgejo` | `node-`, `go-`, `python-` and `bun-version`, `container:` and `image:` images, `uses: docker://…` |
| `action.yml`, `action.yaml` | `runs.using: nodeNN` and `docker://` images |
| Any other `.yml` or `.yaml`, such as Kubernetes manifests and Compose files | `image:` values |
| `*.list`, `*.sources`, Dockerfiles | dated `snapshot.debian.org` and `snapshot.ubuntu.com` URLs |

An image reference is judged by its repository name and tag, wherever it is
pulled from: `node`, `golang`, `rust`, `python`, `bun`, `ubuntu`, `debian` and
`alpine`. A tag variant names a second product: `bookworm` and `noble` select
Debian or Ubuntu by codename, `alpine3.20` selects Alpine, and a distroless
`…-debian12` or `nodejs22-…` repository selects Debian or Node.js. A `FROM` of
an earlier stage, `scratch`, an untagged or `latest` image, or an argument
without a value is not judged. npm, pnpm, Yarn and BusyBox have no end-of-life
data and are not judged.

## How a pin is judged

The pin selects a release cycle: the cycle whose name is the version or its
longest dotted prefix (`1.22` for Go `1.22.3`, `1` for Bun `1.3.9`), or the
cycle whose codename starts with the word (`bookworm`, `noble`, `iron`).

| Condition | Result |
| --- | --- |
| The cycle reached end of life 30 or more days ago | **finding**: fails `ci --policy=strict` and `--fail-on-advisory` |
| The cycle reached end of life less than 30 days ago | warning naming the day strict scans start failing |
| The cycle reaches end of life within 90 days | warning |
| The cycle has left active support (for example Debian security support, or Node.js moving to maintenance LTS) | warning |
| An exact pin trails its cycle's newest release | warning, except one patch behind a release younger than 7 days |
| An apt snapshot is more than 90 days old | warning |

The 30-day grace period exists because Go and Rust end a cycle the day its
successor ships, and a minimum-release-age policy holds that successor back for
a week. A lower bound such as `engines.node: ">=20"` is judged only by its
cycle: declaring support for an end-of-life runtime is a finding, but a range
cannot trail.

Warnings never change the exit code.

## Data

Each product is one endoflife.date v1 document,
`https://endoflife.date/api/v1/products/<product>/`, stored as
`<data dir>/eol/<product>.json`: `alpine-linux`, `bun`, `debian`, `go`,
`nodejs`, `python`, `rust` and `ubuntu`. A document must have schema 1.x, name
its product, list at least one release and carry valid dates.

- `supplychain update` downloads every document.
- `supplychain ci --refresh-eol` downloads them before scanning. The composite
  action does this by default (`refresh-eol: true`).
- Offline CI supplies them in the advisory bundle as `data/eol/<product>.json`
  and points `SUPPLYCHAIN_DATA_DIR` at a copy of `data`.
- `SUPPLYCHAIN_EOL_URL` replaces the origin, for a mirror.

A download writes nothing unless every document validates.

When a pinned product's document is missing, a strict scan reports
`runtime_eol` as a required incomplete check and exits 3. An ordinary scan
skips the check and prints a note saying how to get the data.

## Accepting an end-of-life pin

A dated, reviewed exception in the source policy accepts one product cycle:

```json
{
  "kind": "eol",
  "package": "nodejs",
  "cycle": "20",
  "reason": "the SDK supports Node.js 20 users until the 2026-12 release",
  "owner": "@sdk",
  "expires": "2026-12-01"
}
```

`package` is the endoflife.date product name and `cycle` its release cycle
name, both as reported in the finding. The suppressed finding stays in the
report with its reason, owner and expiry, and an expired exception fails the
scan, as for `osv` and `drift` exceptions.
