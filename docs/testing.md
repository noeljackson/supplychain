# Security test layers

`go test ./...` is the hermetic suite. It uses temporary Git repositories,
local subprocess fixtures, and `httptest` servers; it does not require public
registry or advisory services. Fuzz seed corpora cover IOC, npm, Bun, OSV, and
external-tool JSON parsers.

`scripts/check_go_coverage.py` enforces package-level floors for critical
orchestration, parser, updater, policy, reporting, and external-tool
boundaries. Floors are intentionally below current coverage and are justified
in the script so they detect regression without coupling CI to line-level
implementation details.

Tests that contact public npm, OSV, GitHub, or container registries must use the
`network` build tag and live outside the default suite:

```bash
go test -tags=network ./...
```

CI runs only hermetic tests by default. Network tests are validation aids, not
a merge gate whose transient failure could be confused with scanner behavior.
