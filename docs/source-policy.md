# Source advisory policy

Malware IOCs, payload names, typosquats, signature failures, and maintainer
changes are always enforced. A source policy can only tune OSV vulnerability
advisories and manifest/lockfile drift.

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
    }
  ]
}
```

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
