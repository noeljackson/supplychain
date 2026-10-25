# Source advisory policy

Malware IOCs, payload names, typosquats, signature failures, and maintainer
changes are always enforced. A source policy can only tune OSV vulnerability
advisories, manifest/lockfile drift and end-of-life runtime findings, and name
extra lockfiles for the OSV advisory check to read.

By default every OSV advisory and drift finding is reported. Strict mode fails
on them. To set a threshold, commit `.supplychain/source-policy.json`:

```json
{
  "schema_version": 1,
  "advisories": {
    "minimum_severity": "high",
    "only_fixed": true
  },
  "exceptions": [
    {
      "kind": "osv",
      "advisory_id": "GHSA-xxxx-xxxx-xxxx",
      "package": "example",
      "reason": "upgrade is blocked by the runtime migration",
      "owner": "@security",
      "expires": "2026-08-31"
    },
    {
      "kind": "drift",
      "package": "generated-fixture",
      "drift_reason": "missing-from-lockfile",
      "reason": "fixture intentionally has no production lockfile",
      "owner": "@build",
      "expires": "2026-08-31"
    },
    {
      "kind": "eol",
      "package": "nodejs",
      "cycle": "20",
      "reason": "the SDK supports Node.js 20 users until its next major",
      "owner": "@sdk",
      "expires": "2026-12-01"
    }
  ]
}
```

An `eol` exception names an endoflife.date product and release cycle exactly as
the finding reports them; see [runtime end of life](runtime-eol.md). Older
scanners reject `cycle` and `kind: "eol"`, so move the scanner first.

`minimum_severity` accepts `any`, `low`, `moderate`, `high`, or `critical`.
Unknown severities remain reportable and fail conservatively. `only_fixed`
suppresses advisories that do not advertise a fixed version.

Policy precedence is:

1. IOC and compromise indicators are evaluated outside this policy and cannot
   be suppressed.
2. An exact package plus advisory/drift exception is applied.
3. `minimum_severity` is applied.
4. `only_fixed` is applied.

Every suppressed finding remains in human and JSON output with its reason,
owner, and expiry. Expired exceptions fail the scan instead of being ignored.
The policy must be Git-tracked, contained by the scan target, regular,
non-symlinked, valid JSON, and no larger than 64 KiB. External paths, unknown
fields, duplicate selectors, and trailing JSON are rejected.

## Lockfiles with non-standard names

The OSV advisory check finds lockfiles by their standard names (`Cargo.lock`,
`package-lock.json`, `go.mod`, and so on). A lockfile kept under another name,
such as an image's `deployments/docker/derp.Cargo.lock`, is not read unless the
policy names it:

```json
{
  "schema_version": 1,
  "advisories": {"minimum_severity": "high", "only_fixed": true},
  "exceptions": [],
  "lockfiles": ["deployments/docker/*.Cargo.lock"]
}
```

Each entry is a target-relative pattern (`*`, `?` and `[...]` within one path
segment). Its file name must be the format name or end in `.<format>`, which
says how the file is parsed: `Cargo.lock`, `package-lock.json`,
`pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `go.mod`, `requirements.txt`,
`poetry.lock`, `Pipfile.lock`, `uv.lock`, `Gemfile.lock`, `composer.lock`,
`pom.xml` or `gradle.lockfile`. The named lockfiles fail closed:
- a pattern that matches no file fails the OSV check;
- so does a matched file that is untracked, a symlink or not a regular file;
- so does a file osv-scanner cannot parse.

Advisories found in these files follow the same thresholds and exceptions as
any other lockfile. Older scanners reject a policy with `lockfiles` as an
unknown field, so move the scanner first.
