//! Dumps the constraint x version truth table for the parity harness.
//!
//! Reads the same `parity/semver-matrix.txt` the Go probe reads, and emits the
//! same line format, so any divergence in constraint semantics shows up as a
//! diff rather than as a silently different set of flagged dependencies.

use semver::Version;
use supplychain_semver::Constraint;

fn read_matrix(path: &str) -> std::io::Result<(Vec<String>, Vec<String>)> {
    let raw = std::fs::read_to_string(path)?;
    let (mut specs, mut versions) = (Vec::new(), Vec::new());
    let mut section = "";
    for line in raw.lines() {
        let line = line.trim();
        match line {
            "[specs]" => section = "specs",
            "[versions]" => section = "versions",
            _ => {
                if line.len() < 2 || !line.starts_with('\'') || !line.ends_with('\'') {
                    continue;
                }
                let value = line[1..line.len() - 1].to_string();
                match section {
                    "specs" => specs.push(value),
                    "versions" => versions.push(value),
                    _ => {}
                }
            }
        }
    }
    Ok((specs, versions))
}

fn main() -> std::io::Result<()> {
    let (specs, versions) = read_matrix("parity/semver-matrix.txt")?;
    for spec in &specs {
        let Ok(constraint) = Constraint::parse(spec) else {
            println!("CONSTRAINT\t{spec:?}\tPARSE_ERR");
            continue;
        };
        for raw in &versions {
            let Ok(version) = Version::parse(raw) else {
                continue;
            };
            println!(
                "CONSTRAINT\t{spec:?}\t{raw}\t{}",
                constraint.matches(&version)
            );
        }
    }
    Ok(())
}
