# Vendored npm artifacts

A file copied from a package CDN or npm tarball is no longer covered by a
package-manager lockfile. A checksum next to the copied file detects later
local changes, but it does not prove that the reviewed bytes came from the npm
package and path claimed by the repository.

Supplychain closes that gap with an opt-in tracked manifest at
`.supplychain/vendor-artifacts.json`. Both `supplychain scan` and strict
`supplychain ci` discover it automatically.

The check also supplies a non-optional coverage guard. Every tracked
`*.min.js`, `*.min.mjs`, `*.min.cjs`, and `*.min.css` file must be declared in
the manifest. Removing the manifest does not disable this requirement: an
undeclared minified asset is itself a blocking finding. Tracked runtime HTML,
JavaScript, TypeScript, and CSS are also rejected when they reference common
package CDNs such as unpkg, jsDelivr npm, esm.sh, or Skypack.

## Manifest

```json
{
  "schema_version": 1,
  "npm": [
    {
      "package": "htmx.org",
      "version": "2.0.10",
      "member": "dist/htmx.min.js",
      "path": "web/vendor/htmx-2.0.10.min.js",
      "integrity": "sha512-REGISTRY_TARBALL_INTEGRITY",
      "size": 51238,
      "sha384": "sha384-H5SrcfygHmAuTDZphMHqBJLc3FhssKjG7w/CeCpFReSfwBWDTKpkzPP8c+cLsK+V"
    }
  ]
}
```

Each entry binds all of the following:

- an exact npm package name and version;
- an exact regular-file path below the tarball `package/` root;
- an exact tracked local repository path;
- the reviewed npm tarball SHA-512 integrity;
- the expected member byte length and SHA-384, suitable for browser SRI.

The manifest and every local artifact must already be tracked by Git. During
an update, stage them before running the scanner locally; CI receives the
committed tree.

## Verification boundary

The scanner does not execute repository code, lifecycle scripts, or package
code. It:

1. resolves the exact version from the public npm registry;
2. compares current registry tarball integrity with the reviewed manifest;
3. verifies an npm registry ECDSA signature over that integrity;
4. accepts only HTTPS tarballs on `registry.npmjs.org`, including redirects;
5. downloads at most 50 MiB and verifies the compressed SHA-512 before parsing;
6. parses gzip/tar with path, link, duplicate-member, per-file, and total-size
   protections;
7. extracts exactly `package/<member>` and compares its size, SHA-384, and
   bytes with the tracked local file.

This is provenance and coverage enforcement, not a claim that arbitrary
JavaScript can be classified as malicious from syntax alone. First-party
source still receives normal review and secret scanning; minified third-party
browser code cannot enter the tree without a declared signed-package binding.

Network or registry-key failures are coverage failures. Signature, integrity,
archive-safety, and byte mismatches are blocking supply-chain findings.

The npm registry signature authenticates the published tarball. It does not
claim that an upstream Git tag is signed, nor does an unsigned Git tag replace
registry verification. If the package advertises Sigstore provenance, that is
a separate additional signal; provenance verification remains tracked
independently.

## Update workflow

1. Choose an exact version that has passed the repository cooldown and owner
   review.
2. Obtain the npm registry `dist.integrity` value and copy the exact tar member
   without running an installer or lifecycle script.
3. Record the member byte length and SHA-384 in the manifest.
4. Stage the manifest and artifact so the reviewed-file boundary is active.
5. Run `supplychain ci --policy=strict .`.
6. Review the package/version, integrity, local path, digest, and scanner
   output together in one pull request.

Never replace the exact version with a tag such as `latest`, weaken the digest,
or add an arbitrary download host. Packages outside the public npm registry
need a different verifier with an equally explicit trust root.
