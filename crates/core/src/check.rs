//! Coverage modelling: whether an individual scanner check actually ran.
//!
//! Ported from `internal/check` in the Go implementation. The JSON shape is
//! part of the report envelope contract and must not drift.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Describes coverage independently from whether a check found anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Disabled,
    NotApplicable,
    Completed,
    Incomplete,
    Failed,
}

impl Status {
    /// A gap is an enabled check that did not complete.
    fn is_gap(self) -> bool {
        matches!(self, Status::Incomplete | Status::Failed)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Status::Disabled => "disabled",
            Status::NotApplicable => "not_applicable",
            Status::Completed => "completed",
            Status::Incomplete => "incomplete",
            Status::Failed => "failed",
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The coverage outcome for one named check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    pub status: Status,
    pub required: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub diagnostic: String,
    pub duration_ms: i64,
}

/// Maps stable check identifiers to their result.
///
/// A `BTreeMap` rather than a `HashMap`: Go's `encoding/json` emits map keys in
/// sorted order, so ordered iteration is required for byte-identical output.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Coverage(pub BTreeMap<String, CheckResult>);

impl Coverage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one check result, leaving duration at zero.
    pub fn set(
        &mut self,
        name: impl Into<String>,
        status: Status,
        required: bool,
        diagnostic: impl Into<String>,
    ) {
        self.0.insert(
            name.into(),
            CheckResult {
                status,
                required,
                diagnostic: diagnostic.into(),
                duration_ms: 0,
            },
        );
    }

    /// Records elapsed wall time after `set` has established the outcome.
    ///
    /// A duration for a check that was never `set` is dropped rather than
    /// inventing a result, matching the Go behaviour of writing back a
    /// zero-valued struct only for keys the caller already touched.
    pub fn set_duration(&mut self, name: &str, duration_ms: i64) {
        if let Some(result) = self.0.get_mut(name) {
            result.duration_ms = duration_ms;
        }
    }

    pub fn get(&self, name: &str) -> Option<&CheckResult> {
        self.0.get(name)
    }

    /// Reports any enabled check that did not complete.
    pub fn has_gaps(&self) -> bool {
        self.0.values().any(|r| r.status.is_gap())
    }

    /// Reports an incomplete or failed *required* check.
    pub fn has_required_gaps(&self) -> bool {
        self.0.values().any(|r| r.required && r.status.is_gap())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &CheckResult)> {
        self.0.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_gaps() {
        let mut coverage = Coverage::new();
        coverage.set("completed", Status::Completed, true, "");
        coverage.set("optional", Status::Incomplete, false, "fixture");
        assert!(
            coverage.has_gaps(),
            "optional incomplete check should be a coverage gap"
        );
        assert!(
            !coverage.has_required_gaps(),
            "optional incomplete check should not be a required gap"
        );

        coverage.set("required", Status::Failed, true, "fixture");
        assert!(
            coverage.has_required_gaps(),
            "required failed check should be a required gap"
        );
    }

    #[test]
    fn set_duration_only_touches_existing_checks() {
        let mut coverage = Coverage::new();
        coverage.set("osv", Status::Completed, true, "");
        coverage.set_duration("osv", 42);
        coverage.set_duration("never-set", 99);

        assert_eq!(coverage.get("osv").unwrap().duration_ms, 42);
        assert!(coverage.get("never-set").is_none());
    }

    #[test]
    fn status_serialises_to_the_go_wire_strings() {
        let cases = [
            (Status::Disabled, "\"disabled\""),
            (Status::NotApplicable, "\"not_applicable\""),
            (Status::Completed, "\"completed\""),
            (Status::Incomplete, "\"incomplete\""),
            (Status::Failed, "\"failed\""),
        ];
        for (status, want) in cases {
            assert_eq!(serde_json::to_string(&status).unwrap(), want);
        }
    }

    #[test]
    fn empty_diagnostic_is_omitted_and_keys_are_sorted() {
        let mut coverage = Coverage::new();
        coverage.set("osv", Status::Completed, true, "");
        coverage.set("manifest_ioc", Status::Completed, true, "note");

        let encoded = serde_json::to_string(&coverage).unwrap();
        assert_eq!(
            encoded,
            r#"{"manifest_ioc":{"status":"completed","required":true,"diagnostic":"note","duration_ms":0},"osv":{"status":"completed","required":true,"duration_ms":0}}"#
        );
    }
}
