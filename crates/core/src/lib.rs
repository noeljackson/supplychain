//! Shared types for the supplychain scanner: check coverage, findings, and the
//! versioned report contract.

pub mod check;

pub use check::{CheckResult, Coverage, Status};
