//! Loading and matching of indicator-of-compromise data.
//!
//! Ported from `internal/ioc` in the Go implementation. The parsing rules are
//! reproduced exactly, including their tolerance of malformed lines: the data
//! files are human-edited, and a typo should degrade one indicator rather than
//! fail the scan.

use std::borrow::Cow;
use std::io;
use std::path::{Path, PathBuf};

use semver::Version;

pub mod semver_lenient;

pub use semver_lenient::parse_lenient;

/// Basename of the malicious `name@version` list.
pub const PACKAGES: &str = "packages.txt";
/// Basename of the list of package names malicious at every version.
pub const BLOCKED_PACKAGE_NAMES: &str = "blocked-package-names.txt";
/// Basename of the command-and-control domain list.
pub const C2_DOMAINS: &str = "c2-domains.txt";
/// Basename of the host persistence path list.
pub const PERSISTENCE_PATHS: &str = "persistence-paths.txt";
/// Basename of the `author<TAB>subject` dead-drop signature list.
pub const DEAD_DROP_SIGNATURES: &str = "dead-drop-signatures.txt";
/// Basename of the dropped-payload filename list.
pub const PAYLOAD_FILENAMES: &str = "payload-filenames.txt";

/// Every IOC data file shipped with the scanner, with its compiled-in contents.
const EMBEDDED: &[(&str, &str)] = &[
    (PACKAGES, include_str!("../../../iocs/packages.txt")),
    (
        BLOCKED_PACKAGE_NAMES,
        include_str!("../../../iocs/blocked-package-names.txt"),
    ),
    (C2_DOMAINS, include_str!("../../../iocs/c2-domains.txt")),
    (
        PERSISTENCE_PATHS,
        include_str!("../../../iocs/persistence-paths.txt"),
    ),
    (
        DEAD_DROP_SIGNATURES,
        include_str!("../../../iocs/dead-drop-signatures.txt"),
    ),
    (
        PAYLOAD_FILENAMES,
        include_str!("../../../iocs/payload-filenames.txt"),
    ),
];

/// Returns the compiled-in contents of an IOC file, if it is one we ship.
pub fn embedded(name: &str) -> Option<&'static str> {
    EMBEDDED
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, contents)| *contents)
}

/// Resolves IOC files by basename.
///
/// Mirrors `cmd.Globals.OpenIOC`: an on-disk snapshot takes precedence over the
/// compiled-in defaults, so a refreshed snapshot is picked up without a rebuild.
pub trait Source {
    fn open(&self, name: &str) -> io::Result<Cow<'static, str>>;
}

/// Serves only the compiled-in defaults. Used by CI, where the snapshot must be
/// exactly the one pinned in the scanner source.
#[derive(Debug, Clone, Copy, Default)]
pub struct Embedded;

impl Source for Embedded {
    fn open(&self, name: &str) -> io::Result<Cow<'static, str>> {
        embedded(name).map(Cow::Borrowed).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("unknown IOC file {name}"))
        })
    }
}

/// Prefers `<dir>/<name>` on disk, falling back to the compiled-in default.
#[derive(Debug, Clone)]
pub struct DataDirFirst {
    dir: PathBuf,
}

impl DataDirFirst {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

impl Source for DataDirFirst {
    fn open(&self, name: &str) -> io::Result<Cow<'static, str>> {
        // Reject anything that is not a plain basename: an IOC name is never
        // caller-controlled today, but a traversal here would read arbitrary
        // files into the matcher set.
        if name.is_empty() || Path::new(name).components().count() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid IOC file name {name}"),
            ));
        }
        match std::fs::read_to_string(self.dir.join(name)) {
            Ok(contents) => Ok(Cow::Owned(contents)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Embedded.open(name),
            Err(err) => Err(err),
        }
    }
}

/// One line of `packages.txt`: a `name@version` pair treated as malicious.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageIoc {
    pub name: String,
    pub version: String,
    /// The parsed form of `version`, when it parses. Lets range containment be
    /// answered semantically rather than by string equality.
    pub parsed: Option<Version>,
}

/// Strips a trailing comment and surrounding whitespace, matching the Go
/// loader: the first `#` anywhere on the line begins the comment.
fn strip_comment(line: &str) -> &str {
    let line = line.trim();
    match line.split_once('#') {
        Some((head, _)) => head.trim(),
        None => line,
    }
}

/// Parses `packages.txt` contents. Malformed lines are skipped silently.
pub fn parse_packages(text: &str) -> Vec<PackageIoc> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = strip_comment(line);
        if line.is_empty() {
            continue;
        }
        // Find the LAST '@': scoped packages carry one in the name (@scope/name).
        // An '@' at index 0 is the scope marker of a version-less line, not a
        // separator, so it is rejected the same way Go's `at <= 0` does.
        let Some(at) = line.rfind('@').filter(|&at| at > 0) else {
            continue;
        };
        let (name, version) = (&line[..at], &line[at + 1..]);
        if name.is_empty() || version.is_empty() {
            continue;
        }
        out.push(PackageIoc {
            name: name.to_string(),
            version: version.to_string(),
            parsed: parse_lenient(version),
        });
    }
    out
}

/// Parses a one-per-line list file, stripping comments and blank lines.
pub fn parse_list(text: &str) -> Vec<String> {
    text.lines()
        .map(strip_comment)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

/// Reads and parses `packages.txt` through `source`.
pub fn load_packages(source: &impl Source) -> io::Result<Vec<PackageIoc>> {
    Ok(parse_packages(&source.open(PACKAGES)?))
}

/// Reads and parses a one-per-line list file through `source`.
pub fn load_list(source: &impl Source, name: &str) -> io::Result<Vec<String>> {
    Ok(parse_list(&source.open(name)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scoped_names_by_splitting_on_the_last_at() {
        let parsed = parse_packages("@tanstack/router-core@1.169.5\n");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "@tanstack/router-core");
        assert_eq!(parsed[0].version, "1.169.5");
        assert_eq!(parsed[0].parsed.as_ref().unwrap().to_string(), "1.169.5");
    }

    #[test]
    fn skips_comments_blanks_and_malformed_lines() {
        let text = concat!(
            "# leading comment\n",
            "\n",
            "   \n",
            "good@1.0.0\n",
            "trailing@1.0.1 # inline comment\n",
            "noversion\n",
            "@scope\n",
            "empty@\n",
            "@1.0.0\n",
            "unparseable@not-a-version\n",
        );
        let parsed = parse_packages(text);
        let names: Vec<_> = parsed.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["good", "trailing", "unparseable"]);
        assert_eq!(parsed[1].version, "1.0.1");
        // Kept as an indicator even though the version does not parse: exact
        // string matching still works, only range matching degrades.
        assert_eq!(parsed[2].version, "not-a-version");
        assert!(parsed[2].parsed.is_none());
    }

    #[test]
    fn list_parsing_strips_comments_and_blanks() {
        let text = "# header\n\nevil.example\n  spaced.example  # why\n\n";
        assert_eq!(parse_list(text), ["evil.example", "spaced.example"]);
    }

    #[test]
    fn embedded_source_serves_every_shipped_file() {
        for (name, _) in EMBEDDED {
            let contents = Embedded.open(name).expect("embedded file should resolve");
            assert!(!contents.is_empty(), "{name} should not be empty");
        }
        assert!(Embedded.open("nope.txt").is_err());
    }

    #[test]
    fn shipped_packages_and_blocked_names_parse_into_populated_sets() {
        let packages = load_packages(&Embedded).unwrap();
        assert!(packages.len() > 100, "saw {} packages", packages.len());
        assert!(packages.iter().all(|p| !p.name.is_empty()));

        let blocked = load_list(&Embedded, BLOCKED_PACKAGE_NAMES).unwrap();
        assert!(blocked.len() > 100, "saw {} blocked names", blocked.len());
        assert!(blocked.iter().all(|name| !name.contains('#')));
    }

    #[test]
    fn data_dir_prefers_disk_then_falls_back_to_embedded() {
        let dir = std::env::temp_dir().join(format!("supplychain-ioc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(PACKAGES), "override@9.9.9\n").unwrap();
        let source = DataDirFirst::new(&dir);

        let packages = load_packages(&source).unwrap();
        assert_eq!(packages.len(), 1, "on-disk snapshot should win");
        assert_eq!(packages[0].name, "override");

        // No override on disk for this one, so the embedded default is served.
        let blocked = load_list(&source, BLOCKED_PACKAGE_NAMES).unwrap();
        assert!(blocked.len() > 100);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn data_dir_rejects_path_traversal() {
        let source = DataDirFirst::new("/nonexistent");
        for name in ["../packages.txt", "a/b.txt", "/etc/passwd", ""] {
            assert!(source.open(name).is_err(), "{name} should be rejected");
        }
    }
}
