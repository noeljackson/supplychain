//! Shared types for the supplychain scanner: check coverage, findings, and the
//! versioned report contract.

pub mod check;
pub mod json_compat;

pub use check::{CheckResult, Coverage, Status};
