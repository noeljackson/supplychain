//! Lenient version parsing compatible with `github.com/Masterminds/semver/v3`.
//!
//! The Go implementation calls `semver.NewVersion`, which is deliberately more
//! permissive than the semver specification: it accepts a lowercase `v` prefix,
//! omitted minor/patch components, and leading zeros in the numeric core,
//! coercing `v1`, `1.2`, and `01.2.3` alike. The `semver` crate is strict, so
//! partial versions would silently fail to parse and change matching behaviour.
//!
//! The acceptance rules below were derived by running `semver.NewVersion` over a
//! probe corpus; `tests::matches_masterminds_probe_corpus` records that corpus
//! and its observed Go results verbatim. Regenerate it against the Go library
//! before changing anything here.

use semver::{BuildMetadata, Prerelease, Version};

/// Parses a version the way Masterminds' `NewVersion` does.
///
/// Returns `None` for input Masterminds would reject, mirroring the Go code's
/// "record the raw string, leave `Parsed` nil" behaviour.
///
/// Note the deliberate absence of trimming: Masterminds rejects surrounding
/// whitespace, and callers strip it from the line before splitting.
pub fn parse_lenient(input: &str) -> Option<Version> {
    if input.is_empty() {
        return None;
    }
    // Optional `v` prefix. Masterminds accepts only lowercase.
    let rest = input.strip_prefix('v').unwrap_or(input);

    // Build metadata is everything after the first '+'.
    let (rest, build) = match rest.split_once('+') {
        Some((head, meta)) => (head, Some(meta)),
        None => (rest, None),
    };

    // Prerelease is everything after the first '-'. The numeric core never
    // contains a hyphen, so splitting on the first one is unambiguous.
    let (core, pre) = match rest.split_once('-') {
        Some((head, pre)) => (head, Some(pre)),
        None => (rest, None),
    };

    // `split` always yields at least one element, so an empty core is caught by
    // the emptiness check below rather than passing silently as zero fields.
    let mut numbers = [0u64; 3];
    for (index, part) in core.split('.').enumerate() {
        if index == 3 {
            return None; // more than major.minor.patch
        }
        // Leading zeros are accepted here and normalised away, matching Go.
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        numbers[index] = part.parse().ok()?;
    }

    // An empty prerelease or build segment ("1.2.3-", "1.2.3+") is rejected by
    // Masterminds, but `Prerelease::new("")` and `BuildMetadata::new("")` both
    // succeed, so reject explicitly rather than relying on the crate.
    let prerelease = match pre {
        Some("") => return None,
        Some(pre) => Prerelease::new(pre).ok()?,
        None => Prerelease::EMPTY,
    };
    let build = match build {
        Some("") => return None,
        Some(build) => BuildMetadata::new(build).ok()?,
        None => BuildMetadata::EMPTY,
    };

    Some(Version {
        major: numbers[0],
        minor: numbers[1],
        patch: numbers[2],
        pre: prerelease,
        build,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_lenient;

    /// Probe corpus and expected results captured from
    /// `github.com/Masterminds/semver/v3 v3.5.0`. `None` means Go returned an
    /// error; `Some(s)` means Go parsed it and `Version.String()` produced `s`.
    const PROBE: &[(&str, Option<&str>)] = &[
        ("1.2.3", Some("1.2.3")),
        ("v1.2.3", Some("1.2.3")),
        ("V1.2.3", None),
        ("1.2", Some("1.2.0")),
        ("1", Some("1.0.0")),
        ("v2", Some("2.0.0")),
        (" 1.2.3 ", None),
        ("1.2.3-beta.1", Some("1.2.3-beta.1")),
        ("1.2.3+build.5", Some("1.2.3+build.5")),
        ("1.2.3-rc.1+build.5", Some("1.2.3-rc.1+build.5")),
        ("0.0.19", Some("0.0.19")),
        ("", None),
        ("   ", None),
        ("abc", None),
        ("1.2.3.4", None),
        ("1..3", None),
        ("1.x", None),
        ("latest", None),
        ("^1.2.3", None),
        ("-1.0.0", None),
        ("1.2.3-", None),
        ("1.2.3+", None),
        ("01.2.3", Some("1.2.3")),
        ("1.02.3", Some("1.2.3")),
        ("v1.2.3-alpha", Some("1.2.3-alpha")),
        ("1.2.3-01", None),
        ("1.0.0-alpha+001", Some("1.0.0-alpha+001")),
    ];

    #[test]
    fn matches_masterminds_probe_corpus() {
        for (input, want) in PROBE {
            let got = parse_lenient(input).map(|v| v.to_string());
            assert_eq!(
                got.as_deref(),
                *want,
                "parse_lenient({input:?}) diverged from Masterminds"
            );
        }
    }
}
