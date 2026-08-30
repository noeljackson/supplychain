//! Repository automation for the Go -> Rust port.
//!
//! `cargo xtask parity` runs every probe declared in `parity.toml`, comparing
//! the output of the Go implementation against the Rust one. Probes marked
//! `required` fail the build on divergence; probes still `pending` report their
//! difference without failing, so the port can land one check at a time.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde::Deserialize;

/// How strictly a probe's divergence is treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum State {
    /// Divergence is a bug and fails the build.
    Required,
    /// Not ported yet: divergence is reported but tolerated.
    Pending,
}

#[derive(Debug, Deserialize)]
struct Probe {
    state: State,
    #[serde(default)]
    description: String,
    go: Vec<String>,
    rust: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    #[serde(default)]
    probes: BTreeMap<String, Probe>,
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("parity") => {
            let filter = args.next();
            match run_parity(filter.as_deref()) {
                Ok(true) => ExitCode::SUCCESS,
                Ok(false) => ExitCode::FAILURE,
                Err(err) => {
                    eprintln!("xtask: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(other) => {
            eprintln!("xtask: unknown task {other:?}");
            eprintln!("usage: cargo xtask parity [probe]");
            ExitCode::FAILURE
        }
        None => {
            eprintln!("usage: cargo xtask parity [probe]");
            ExitCode::FAILURE
        }
    }
}

/// The repository root, derived from this crate's manifest location so the task
/// behaves the same regardless of the caller's working directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/xtask sits two levels below the repository root")
        .to_path_buf()
}

/// Runs the declared probes. Returns whether the gate passed.
fn run_parity(filter: Option<&str>) -> Result<bool, String> {
    let root = repo_root();
    let manifest_path = root.join("parity.toml");
    let raw = std::fs::read_to_string(&manifest_path)
        .map_err(|err| format!("read {}: {err}", manifest_path.display()))?;
    let manifest: Manifest =
        toml::from_str(&raw).map_err(|err| format!("parse {}: {err}", manifest_path.display()))?;

    let selected: Vec<_> = manifest
        .probes
        .iter()
        .filter(|(name, _)| filter.is_none_or(|want| want == name.as_str()))
        .collect();

    if selected.is_empty() {
        return Err(match filter {
            Some(name) => format!("no probe named {name:?} in parity.toml"),
            None => "parity.toml declares no probes".to_string(),
        });
    }

    let mut failed = Vec::new();
    let mut diverged_pending = Vec::new();

    for (name, probe) in selected {
        eprintln!("== {name}: {}", probe.description);
        let go = capture(&root, &probe.go)?;
        let rust = capture(&root, &probe.rust)?;

        if go == rust {
            let lines = go.lines().count();
            println!("PASS     {name} ({lines} lines identical)");
            continue;
        }

        match probe.state {
            State::Required => {
                println!("DIVERGED {name}  [required]");
                report_difference(&go, &rust);
                failed.push(name.clone());
            }
            State::Pending => {
                println!("pending  {name}  (not yet at parity)");
                diverged_pending.push(name.clone());
            }
        }
    }

    if !diverged_pending.is_empty() {
        println!(
            "\n{} probe(s) still pending: {}",
            diverged_pending.len(),
            diverged_pending.join(", ")
        );
    }
    if failed.is_empty() {
        println!("\nparity gate passed");
        Ok(true)
    } else {
        println!("\nparity gate FAILED for: {}", failed.join(", "));
        Ok(false)
    }
}

/// Runs one side of a probe and returns its stdout.
fn capture(root: &Path, argv: &[String]) -> Result<String, String> {
    let (program, rest) = argv
        .split_first()
        .ok_or_else(|| "probe command is empty".to_string())?;
    let output = Command::new(program)
        .args(rest)
        .current_dir(root)
        .output()
        .map_err(|err| format!("run {}: {err}", argv.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "{} exited with {}\n{}",
            argv.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|err| format!("{} produced non-UTF-8 output: {err}", argv.join(" ")))
}

/// Prints the first few differing lines. Deliberately minimal: enough to locate
/// the divergence without taking on a diff dependency.
fn report_difference(go: &str, rust: &str) {
    const CONTEXT: usize = 10;

    let go_lines: Vec<_> = go.lines().collect();
    let rust_lines: Vec<_> = rust.lines().collect();
    println!(
        "  go produced {} lines, rust {}",
        go_lines.len(),
        rust_lines.len()
    );

    let mut shown = 0;
    for index in 0..go_lines.len().max(rust_lines.len()) {
        let left = go_lines.get(index).copied();
        let right = rust_lines.get(index).copied();
        if left == right {
            continue;
        }
        if shown == CONTEXT {
            println!("  ... further differences suppressed");
            break;
        }
        println!("  line {}:", index + 1);
        println!("    go   {}", left.unwrap_or("<missing>"));
        println!("    rust {}", right.unwrap_or("<missing>"));
        shown += 1;
    }
}
