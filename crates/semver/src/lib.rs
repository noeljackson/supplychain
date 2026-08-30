//! Version and constraint handling compatible with
//! `github.com/Masterminds/semver/v3`, the library the Go scanner uses.
//!
//! This is deliberately *not* a wrapper around `semver::VersionReq`. Cargo and
//! Masterminds disagree on the meaning of common npm specs -- most importantly
//! a bare `1.2.3`, which Cargo reads as a caret range and Masterminds reads as
//! exact equality. Using `VersionReq` would silently change which dependencies
//! match a malicious-version indicator.
//!
//! Both modules are validated against truth tables captured from the Go library
//! itself; see `parity/semver-matrix.txt` and the `semver-constraints` probe.

pub mod constraint;
pub mod lenient;

pub use constraint::Constraint;
pub use lenient::parse_lenient;
