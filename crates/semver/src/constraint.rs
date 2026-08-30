//! Masterminds-compatible version constraints.
//!
//! Semantics were captured from `github.com/Masterminds/semver/v3` rather than
//! assumed; `parity/semver-matrix.txt` holds the inputs and the
//! `semver-constraints` parity probe diffs this implementation against the Go
//! library over the full truth table.
//!
//! The behaviours worth naming, because they differ from Cargo's `VersionReq`:
//!
//! * A bare `1.2.3` is exact equality, not a caret range.
//! * A partial operand defines a *range*, and operators apply to that range's
//!   edges: `>1.2` excludes all of `1.2.x`, while `<=1.5` includes `1.5.1`.
//! * A version carrying a prerelease matches only when the comparator's own
//!   operand carries one. `*` therefore never matches `1.2.3-alpha`.

use semver::Version;

/// A parsed constraint: a disjunction of conjunctions, as in `^1 || ~2.3`.
#[derive(Debug, Clone)]
pub struct Constraint {
    /// OR of AND-groups. Empty groups are impossible; parsing rejects them.
    groups: Vec<Vec<Comparator>>,
}

/// Why a constraint string could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid constraint: {}", self.0)
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    Tilde,
    Caret,
}

/// An operand: a possibly-partial version, remembering how many fields the
/// author actually wrote. Precision drives every range calculation.
#[derive(Debug, Clone)]
struct Operand {
    version: Version,
    /// 1 for `1`, 2 for `1.2`, 3 for `1.2.3`. A wildcard field truncates
    /// precision, so `1.2.x` has precision 2 and `*` precision 0.
    precision: u8,
}

impl Operand {
    /// Inclusive lower edge of the range this operand denotes.
    fn lower(&self) -> Version {
        self.version.clone()
    }

    /// Exclusive upper edge, or `None` when the operand names an exact point.
    fn upper(&self) -> Option<Version> {
        match self.precision {
            1 => Some(plain(self.version.major + 1, 0, 0)),
            2 => Some(plain(self.version.major, self.version.minor + 1, 0)),
            _ => None,
        }
    }

    fn tilde_upper(&self) -> Version {
        match self.precision {
            1 => plain(self.version.major + 1, 0, 0),
            _ => plain(self.version.major, self.version.minor + 1, 0),
        }
    }

    fn caret_upper(&self) -> Version {
        let (major, minor, patch) = (self.version.major, self.version.minor, self.version.patch);
        if major > 0 {
            plain(major + 1, 0, 0)
        } else if self.precision == 1 {
            plain(1, 0, 0)
        } else if minor > 0 {
            plain(0, minor + 1, 0)
        } else if self.precision == 2 {
            plain(0, 1, 0)
        } else {
            plain(0, 0, patch + 1)
        }
    }
}

fn plain(major: u64, minor: u64, patch: u64) -> Version {
    Version::new(major, minor, patch)
}

#[derive(Debug, Clone)]
struct Comparator {
    op: Op,
    operand: Operand,
    /// A wildcard with no numeric field at all (`*`, `x`, `X`): matches every
    /// non-prerelease version.
    any: bool,
}

impl Comparator {
    fn matches(&self, version: &Version) -> bool {
        // Masterminds gates prereleases per comparator: a version carrying one
        // is only eligible against an operand that carries one too. This is
        // what keeps `*` from matching `1.2.3-alpha`.
        if !version.pre.is_empty() && self.operand.version.pre.is_empty() {
            return false;
        }
        if self.any {
            return true;
        }

        let lower = self.operand.lower();
        let upper = self.operand.upper();

        match self.op {
            Op::Eq => in_range(version, &lower, upper.as_ref()),
            Op::Ne => !in_range(version, &lower, upper.as_ref()),
            // For a partial operand, `>` means "past the whole range".
            Op::Gt => match upper {
                Some(upper) => !below_upper(version, &upper),
                None => *version > lower,
            },
            Op::Gte => *version >= lower,
            Op::Lt => *version < lower,
            // Symmetrically, `<=` on a partial operand admits the whole range.
            Op::Lte => match upper {
                Some(upper) => below_upper(version, &upper),
                None => *version <= lower,
            },
            Op::Tilde => *version >= lower && below_upper(version, &self.operand.tilde_upper()),
            Op::Caret => *version >= lower && below_upper(version, &self.operand.caret_upper()),
        }
    }
}

/// Whether `version` falls in `[lower, upper)`, or equals `lower` exactly when
/// the operand named a point rather than a range.
fn in_range(version: &Version, lower: &Version, upper: Option<&Version>) -> bool {
    match upper {
        Some(upper) => version >= lower && below_upper(version, upper),
        None => version == lower,
    }
}

/// Whether `version` sits below an exclusive upper bound.
///
/// Plain ordering is not enough. Masterminds bounds `^` and `~` by comparing
/// version *fields*, so `^1.2.3-alpha` rejects `2.0.0-rc.1` even though
/// `2.0.0-rc.1 < 2.0.0` under semver ordering: the prerelease belongs to the
/// next major, which is outside the range. A prerelease sharing the boundary's
/// `major.minor.patch` is therefore excluded rather than admitted.
fn below_upper(version: &Version, upper: &Version) -> bool {
    if !version.pre.is_empty()
        && (version.major, version.minor, version.patch) == (upper.major, upper.minor, upper.patch)
    {
        return false;
    }
    version < upper
}

impl Constraint {
    /// Parses a constraint string, rejecting anything Masterminds rejects.
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let mut groups = Vec::new();
        for raw_group in input.split("||") {
            groups.push(parse_group(raw_group)?);
        }
        Ok(Constraint { groups })
    }

    /// Whether `version` satisfies the constraint.
    pub fn matches(&self, version: &Version) -> bool {
        self.groups
            .iter()
            .any(|group| group.iter().all(|c| c.matches(version)))
    }
}

/// Parses one AND-group: comparators joined by whitespace or commas, or a
/// single hyphen range.
fn parse_group(raw: &str) -> Result<Vec<Comparator>, ParseError> {
    let group = raw.trim();
    if group.is_empty() {
        return Err(ParseError(raw.to_string()));
    }
    if let Some(range) = parse_hyphen_range(group)? {
        return Ok(range);
    }
    let comparators: Vec<_> = split_terms(group)
        .map(parse_comparator)
        .collect::<Result<_, _>>()?;
    if comparators.is_empty() {
        return Err(ParseError(raw.to_string()));
    }
    Ok(comparators)
}

/// Recognises `A - B`, which bounds both edges inclusively (with `B`'s upper
/// edge widened when `B` is partial).
fn parse_hyphen_range(group: &str) -> Result<Option<Vec<Comparator>>, ParseError> {
    // Only a hyphen surrounded by whitespace separates a range; a leading `-`
    // is a malformed operand, and `1.2.3-alpha` is a prerelease.
    let Some(index) = group.find(" - ") else {
        // A trailing or leading bare hyphen is malformed rather than a range.
        if group.ends_with(" -") || group.starts_with("- ") {
            return Err(ParseError(group.to_string()));
        }
        return Ok(None);
    };
    let (left, right) = (group[..index].trim(), group[index + 3..].trim());
    if left.is_empty() || right.is_empty() {
        return Err(ParseError(group.to_string()));
    }
    let lower = parse_operand(left)?;
    let upper = parse_operand(right)?;
    Ok(Some(vec![
        Comparator {
            op: Op::Gte,
            operand: lower,
            any: false,
        },
        Comparator {
            op: Op::Lte,
            operand: upper,
            any: false,
        },
    ]))
}

/// Splits an AND-group into comparator terms.
///
/// A term is an optional operator followed by an operand, and Masterminds
/// tolerates whitespace between the two (`>= 1.2.3`). Splitting naively on
/// whitespace would therefore tear `>=` off its version, so operators are
/// consumed together with the operand that follows them.
fn split_terms(group: &str) -> impl Iterator<Item = &str> {
    let bytes = group.as_bytes();
    let mut terms = Vec::new();
    let mut index = 0usize;

    while index < bytes.len() {
        while index < bytes.len() && (bytes[index].is_ascii_whitespace() || bytes[index] == b',') {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        let start = index;
        // Operator characters, then any whitespace separating them from the
        // operand, then the operand itself.
        while index < bytes.len() && matches!(bytes[index], b'=' | b'!' | b'<' | b'>' | b'~' | b'^')
        {
            index += 1;
        }
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        while index < bytes.len() && !bytes[index].is_ascii_whitespace() && bytes[index] != b',' {
            index += 1;
        }
        terms.push(group[start..index].trim());
    }
    terms.into_iter()
}

fn parse_comparator(term: &str) -> Result<Comparator, ParseError> {
    let term = term.trim();
    let (op, rest) = split_operator(term)?;
    let rest = rest.trim();

    // A bare wildcard carries no numeric field at all.
    if matches!(rest, "*" | "x" | "X") {
        return Ok(Comparator {
            op,
            operand: Operand {
                version: plain(0, 0, 0),
                precision: 0,
            },
            any: true,
        });
    }
    Ok(Comparator {
        op,
        operand: parse_operand(rest)?,
        any: false,
    })
}

fn split_operator(term: &str) -> Result<(Op, &str), ParseError> {
    for (token, op) in [
        (">=", Op::Gte),
        ("<=", Op::Lte),
        ("!=", Op::Ne),
        ("=", Op::Eq),
        (">", Op::Gt),
        ("<", Op::Lt),
        ("~", Op::Tilde),
        ("^", Op::Caret),
    ] {
        if let Some(rest) = term.strip_prefix(token) {
            // Masterminds has no `==`; a doubled operator is malformed.
            if rest.starts_with(['=', '<', '>', '!', '~', '^']) {
                return Err(ParseError(term.to_string()));
            }
            return Ok((op, rest));
        }
    }
    Ok((Op::Eq, term))
}

/// Parses a possibly-partial, possibly-wildcarded version operand.
fn parse_operand(raw: &str) -> Result<Operand, ParseError> {
    let error = || ParseError(raw.to_string());
    let text = raw.trim();
    if text.is_empty() {
        return Err(error());
    }
    let text = text.strip_prefix('v').unwrap_or(text);

    let (text, build) = match text.split_once('+') {
        Some((head, meta)) => (head, Some(meta)),
        None => (text, None),
    };
    let (core, pre) = match text.split_once('-') {
        Some((head, pre)) => (head, Some(pre)),
        None => (text, None),
    };

    let mut fields = [0u64; 3];
    let mut precision = 0u8;
    for (index, part) in core.split('.').enumerate() {
        if index == 3 {
            return Err(error());
        }
        if matches!(part, "x" | "X" | "*") {
            // A wildcard field ends the operand: `1.x.3` is not meaningful, and
            // everything after the wildcard is ignored the way `1.x` is.
            break;
        }
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(error());
        }
        fields[index] = part.parse().map_err(|_| error())?;
        precision = (index + 1) as u8;
    }
    if precision == 0 {
        return Err(error());
    }

    let pre = match pre {
        Some("") => return Err(error()),
        Some(pre) => semver::Prerelease::new(pre).map_err(|_| error())?,
        None => semver::Prerelease::EMPTY,
    };
    let build = match build {
        Some("") => return Err(error()),
        Some(build) => semver::BuildMetadata::new(build).map_err(|_| error())?,
        None => semver::BuildMetadata::EMPTY,
    };

    Ok(Operand {
        version: Version {
            major: fields[0],
            minor: fields[1],
            patch: fields[2],
            pre,
            build,
        },
        precision,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(spec: &str, version: &str) -> bool {
        Constraint::parse(spec)
            .unwrap_or_else(|_| panic!("{spec} should parse"))
            .matches(&Version::parse(version).unwrap())
    }

    #[test]
    fn bare_version_is_equality_not_a_caret_range() {
        assert!(matches("1.2.3", "1.2.3"));
        assert!(!matches("1.2.3", "1.2.4"));
        assert!(!matches("1.2.3", "1.3.0"));
    }

    #[test]
    fn partial_operands_denote_ranges_at_their_edges() {
        assert!(
            !matches(">1.2", "1.2.4"),
            "> skips past the whole 1.2 range"
        );
        assert!(matches(">1.2", "1.3.0"));
        assert!(matches("<=1.5", "1.5.1"), "<= admits the whole 1.5 range");
        assert!(!matches("<=1.5", "1.6.0"));
        assert!(matches("=1.2", "1.2.4"));
        assert!(!matches("=1.2", "1.3.0"));
    }

    #[test]
    fn prereleases_need_a_prerelease_operand() {
        assert!(!matches("*", "1.2.3-alpha"));
        assert!(!matches(">=1.2.3", "2.0.0-rc.1"));
        assert!(matches(">=1.2.3-alpha", "2.0.0-rc.1"));
        assert!(matches("1.2.3-alpha", "1.2.3-alpha"));
    }

    #[test]
    fn caret_narrows_as_the_leading_zero_count_grows() {
        assert!(matches("^1.2.3", "1.9.9") && !matches("^1.2.3", "2.0.0"));
        assert!(matches("^0.2.3", "0.2.4") && !matches("^0.2.3", "0.3.0"));
        assert!(matches("^0.0.3", "0.0.3") && !matches("^0.0.3", "0.0.4"));
        assert!(matches("^0.0", "0.0.20") && !matches("^0.0", "0.1.0"));
        assert!(matches("^0", "0.3.0") && !matches("^0", "1.0.0"));
    }

    #[test]
    fn hyphen_range_upper_edge_widens_when_partial() {
        assert!(matches("1.2 - 1.5", "1.5.1"));
        assert!(!matches("1.2.3 - 1.5.0", "1.5.1"));
        assert!(matches("1 - 2", "2.1.0") && !matches("1 - 2", "3.0.0"));
    }

    #[test]
    fn a_prerelease_at_the_upper_boundary_is_outside_the_range() {
        // `^1.2.3-alpha` admits prereleases across major 1 but not the next
        // major, even though `2.0.0-rc.1` sorts below `2.0.0`.
        assert!(matches("^1.2.3-alpha", "1.6.0-alpha"));
        assert!(matches("^1.2.3-alpha", "1.2.4-alpha"));
        assert!(!matches("^1.2.3-alpha", "2.0.0-rc.1"));
        assert!(!matches("^1.2.3-alpha", "2.0.0-alpha"));
        assert!(
            !matches("^1.2.3-alpha", "1.0.0-alpha"),
            "below the lower edge"
        );
        // An operator with no upper bound keeps plain ordering.
        assert!(matches(">=1.2.3-alpha", "3.0.0-alpha"));
    }

    #[test]
    fn rejects_what_masterminds_rejects() {
        for spec in [
            "",
            "  ",
            "latest",
            "workspace:*",
            "==1.2.3",
            "1.2.3 - ",
            "- 1.2.3",
        ] {
            assert!(Constraint::parse(spec).is_err(), "{spec} should not parse");
        }
    }
}
