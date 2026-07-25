# Machine-readable reports and exit codes

`--json` source reports use schema version `1`. The top-level envelope contains
the command, scanner version, target, selected policy and its digest, IOC
snapshot identity, helper versions, outcome, per-check status/timing,
diagnostics, total timing, active findings, and policy-suppressed findings.
Consumers must reject unsupported `schema_version` values.

`scan-all --json` emits one aggregate JSON document with a `reports` array and
an `errors` array. It never concatenates per-repository JSON objects.

The stable process exit codes are:

| Code | Meaning |
| ---: | --- |
| 0 | Clean, or warnings that the selected policy does not fail |
| 1 | Policy-enforced findings |
| 2 | Invalid command usage or arguments |
| 3 | Incomplete coverage or an operational failure |

`doctor --profile=source` checks the default source-scan installation.
`strict`, `image`, `workflows`, and `secrets` profiles additionally require the
helpers used by that execution profile. Missing required capabilities return
exit code 3. Optional missing capabilities remain visible without failing
health.
