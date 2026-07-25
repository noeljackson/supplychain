# Release controls

The tag-triggered workflow references the `release` GitHub environment. Before
publishing a release, configure that environment in repository settings with:

- required reviewers, with self-review disabled;
- deployment tags restricted to `v*`;
- `HOMEBREW_TAP_TOKEN` stored as an environment secret rather than a
  repository-wide secret.

Also add a repository ruleset for tags matching `v*`. Restrict tag creation and
updates to maintainers, require signed tags where the repository plan supports
it, and prevent deletion and non-fast-forward updates. The environment is the
final human approval gate; the tag ruleset controls who can request that gate.

The release workflow pins both GoReleaser and Syft to exact versions, creates an
SBOM for every archive, verifies the archives/checksum/SBOM set exists, and
attests each file. CI runs `scripts/check_release_security.py` to reject
floating tool versions or accidental removal of those controls.

Package-manager provenance remains tracked separately in
[issue #10](https://github.com/noeljackson/supplychain/issues/10).
