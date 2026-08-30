//! Parses `package.json` files and matches declared dependencies against
//! indicator data.
//!
//! Ported from `internal/manifest` in the Go implementation.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use supplychain_ioc::PackageIoc;
use supplychain_semver::Constraint;

/// The parts of a `package.json` the scanner reads.
#[derive(Debug, Default, Deserialize)]
struct PackageJson {
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "peerDependencies")]
    peer_dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: BTreeMap<String, String>,
}

/// A dependency entry that matches, or could resolve to, a known-bad
/// `package@version` indicator.
///
/// Field names are capitalised because the Go struct carries no `json` tags,
/// which makes its Go field names part of the report contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestHit {
    /// Path to the `package.json`, as reached from the scan root.
    #[serde(rename = "File")]
    pub file: String,
    /// `dependencies` | `devDependencies` | `peerDependencies` | `optionalDependencies`
    #[serde(rename = "Section")]
    pub section: String,
    #[serde(rename = "Name")]
    pub name: String,
    /// The raw version spec as written in the manifest.
    #[serde(rename = "Range")]
    pub range: String,
    /// The indicator version the spec matches, or `(any)` for a blocked name.
    #[serde(rename = "BadVersion")]
    pub bad_version: String,
    /// `exact-match` | `range-includes` | `name-blocked` | `wildcard-spec`
    #[serde(rename = "Reason")]
    pub reason: String,
    /// The version `npm install` would pick today. Empty unless registry
    /// resolution ran.
    #[serde(rename = "Resolved")]
    pub resolved: String,
    /// Whether `resolved` is itself a known-bad version, turning "this range
    /// could reach a malicious version" into "the next install will take one".
    #[serde(rename = "ResolvedBad")]
    pub resolved_bad: bool,
}

/// Indicators grouped by package name, for lookup while walking manifests.
pub struct Indicators {
    by_name: BTreeMap<String, Vec<PackageIoc>>,
    blocked: BTreeMap<String, ()>,
}

impl Indicators {
    pub fn new(iocs: &[PackageIoc], blocked_names: &[String]) -> Self {
        let mut by_name: BTreeMap<String, Vec<PackageIoc>> = BTreeMap::new();
        for entry in iocs {
            by_name
                .entry(entry.name.clone())
                .or_default()
                .push(entry.clone());
        }
        Self {
            by_name,
            blocked: blocked_names.iter().map(|n| (n.clone(), ())).collect(),
        }
    }
}

/// Walks `root` for `package.json` files and returns every indicator match.
///
/// `node_modules` and `.git` are skipped wholesale: installed trees are the
/// lockfile scanner's job, and repository metadata is not a manifest.
pub fn scan_repo(root: impl AsRef<Path>, indicators: &Indicators) -> io::Result<Vec<ManifestHit>> {
    let mut hits = Vec::new();
    walk(root.as_ref(), indicators, &mut hits)?;
    Ok(hits)
}

fn walk(path: &Path, indicators: &Indicators, hits: &mut Vec<ManifestHit>) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.is_file() {
        if path.file_name().is_some_and(|name| name == "package.json") {
            hits.extend(scan_file(path, indicators)?);
        }
        return Ok(());
    }
    if !metadata.is_dir() {
        // Symlinks are not followed: a link out of the tree would put files
        // outside the scan target in scope.
        return Ok(());
    }

    let mut entries: Vec<PathBuf> = std::fs::read_dir(path)?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    entries.sort();

    for entry in entries {
        let is_dir = std::fs::symlink_metadata(&entry).is_ok_and(|m| m.is_dir());
        if is_dir {
            let name = entry.file_name().unwrap_or_default().to_owned();
            if name == "node_modules" || name == ".git" {
                continue;
            }
        }
        walk(&entry, indicators, hits)?;
    }
    Ok(())
}

fn scan_file(path: &Path, indicators: &Indicators) -> io::Result<Vec<ManifestHit>> {
    let raw = std::fs::read_to_string(path)?;
    let parsed: PackageJson = serde_json::from_str(&raw)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let file = path.to_string_lossy().into_owned();

    let sections = [
        ("dependencies", &parsed.dependencies),
        ("devDependencies", &parsed.dev_dependencies),
        ("peerDependencies", &parsed.peer_dependencies),
        ("optionalDependencies", &parsed.optional_dependencies),
    ];

    let mut hits = Vec::new();
    for (section, deps) in sections {
        for (name, spec) in deps {
            // A blocked name is malicious at every version, so the spec is
            // irrelevant and no range check is attempted.
            if indicators.blocked.contains_key(name) {
                hits.push(ManifestHit {
                    file: file.clone(),
                    section: section.to_string(),
                    name: name.clone(),
                    range: spec.clone(),
                    bad_version: "(any)".to_string(),
                    reason: "name-blocked".to_string(),
                    resolved: String::new(),
                    resolved_bad: false,
                });
                continue;
            }
            let Some(entries) = indicators.by_name.get(name) else {
                continue;
            };
            for entry in entries {
                if let Some((bad_version, reason)) = match_spec(spec, entry) {
                    hits.push(ManifestHit {
                        file: file.clone(),
                        section: section.to_string(),
                        name: name.clone(),
                        range: spec.clone(),
                        bad_version,
                        reason: reason.to_string(),
                        resolved: String::new(),
                        resolved_bad: false,
                    });
                }
            }
        }
    }
    Ok(hits)
}

/// Decides whether a manifest spec matches a known-bad version, returning the
/// indicator version and the reason.
fn match_spec(spec: &str, bad: &PackageIoc) -> Option<(String, &'static str)> {
    if spec == bad.version {
        return Some((bad.version.clone(), "exact-match"));
    }
    // Range containment is only meaningful when the indicator version parses.
    let parsed = bad.parsed.as_ref()?;

    let Ok(constraint) = Constraint::parse(spec) else {
        // Specs that are not constraints at all: `workspace:*`, git and file
        // URLs. The bare wildcards are handled here only for structural
        // fidelity with the Go code -- they are unreachable, because the
        // constraint parser accepts `*`, `x`, and `X` and they match above.
        if matches!(spec, "*" | "x" | "X") {
            return Some((bad.version.clone(), "wildcard-spec"));
        }
        return None;
    };
    constraint
        .matches(parsed)
        .then(|| (bad.version.clone(), "range-includes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use supplychain_ioc::parse_packages;

    fn indicators(packages: &str, blocked: &[&str]) -> Indicators {
        let blocked: Vec<String> = blocked.iter().map(|s| s.to_string()).collect();
        Indicators::new(&parse_packages(packages), &blocked)
    }

    fn hit_reasons(hits: &[ManifestHit]) -> Vec<(&str, &str, &str)> {
        hits.iter()
            .map(|h| (h.name.as_str(), h.reason.as_str(), h.bad_version.as_str()))
            .collect()
    }

    fn write_manifest(dir: &Path, relative: &str, body: &str) {
        let path = dir.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("supplychain-manifest-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn exact_pin_beats_range_matching() {
        let indicators = indicators("evil@1.2.3\n", &[]);
        let dir = temp_dir("exact");
        write_manifest(&dir, "package.json", r#"{"dependencies":{"evil":"1.2.3"}}"#);
        let hits = scan_repo(&dir, &indicators).unwrap();
        assert_eq!(hit_reasons(&hits), [("evil", "exact-match", "1.2.3")]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn range_containment_uses_masterminds_semantics() {
        let indicators = indicators("evil@1.2.3\n", &[]);
        let dir = temp_dir("range");
        // A bare "1.2.4" is exact equality under Masterminds, so it must not
        // match 1.2.3 the way a Cargo-style caret reading would.
        write_manifest(
            &dir,
            "package.json",
            r#"{"dependencies":{"evil":"^1.2.0"},"devDependencies":{"evil":"1.2.4"}}"#,
        );
        let hits = scan_repo(&dir, &indicators).unwrap();
        assert_eq!(hit_reasons(&hits), [("evil", "range-includes", "1.2.3")]);
        assert_eq!(hits[0].section, "dependencies");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn blocked_names_hit_regardless_of_spec() {
        let indicators = indicators("", &["blocked-pkg"]);
        let dir = temp_dir("blocked");
        write_manifest(
            &dir,
            "package.json",
            r#"{"dependencies":{"blocked-pkg":"github:foo/bar"}}"#,
        );
        let hits = scan_repo(&dir, &indicators).unwrap();
        assert_eq!(
            hit_reasons(&hits),
            [("blocked-pkg", "name-blocked", "(any)")]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unparseable_specs_are_not_matched() {
        let indicators = indicators("evil@1.2.3\n", &[]);
        let dir = temp_dir("unparseable");
        write_manifest(
            &dir,
            "package.json",
            r#"{"dependencies":{"evil":"workspace:*"}}"#,
        );
        assert!(scan_repo(&dir, &indicators).unwrap().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn node_modules_and_git_are_skipped() {
        let indicators = indicators("evil@1.2.3\n", &[]);
        let dir = temp_dir("skips");
        let body = r#"{"dependencies":{"evil":"1.2.3"}}"#;
        write_manifest(&dir, "package.json", body);
        write_manifest(&dir, "node_modules/pkg/package.json", body);
        write_manifest(&dir, ".git/package.json", body);
        write_manifest(&dir, "sub/node_modules/deep/package.json", body);

        let hits = scan_repo(&dir, &indicators).unwrap();
        assert_eq!(hits.len(), 1, "only the root manifest should be scanned");
        std::fs::remove_dir_all(&dir).ok();
    }
}
