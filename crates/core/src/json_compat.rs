//! Go-compatible JSON encoding.
//!
//! The report envelope is written by Go's `encoding/json`, and matching it
//! byte-for-byte means matching two behaviours `serde_json` does not share:
//!
//! * HTML escaping. Go escapes `<`, `>`, and `&` as `\u003c`, `\u003e`, and
//!   `\u0026` by default, so a version range like `>=1.0.0 <2.0.0` is not
//!   written literally. `json.Encoder` has this on unless `SetEscapeHTML(false)`
//!   is called, and `internal/report` does not call it.
//! * Line separator escaping. Go also escapes U+2028 and U+2029, which are
//!   valid in JSON strings but break JavaScript parsers.
//!
//! Indentation matches `enc.SetIndent("", "  ")` plus the trailing newline
//! `json.Encoder.Encode` always writes.

use serde::Serialize;

/// Applies Go's escaping to already-serialised JSON.
///
/// A blanket replacement over the whole document is safe: `<`, `>`, and `&` are
/// not JSON structural characters, so every occurrence is inside a string
/// literal. Quotes and backslashes are already escaped by the serialiser.
fn escape_like_go(json: &str) -> String {
    if !json.contains(['<', '>', '&', '\u{2028}', '\u{2029}']) {
        return json.to_string();
    }
    let mut out = String::with_capacity(json.len() + 16);
    for ch in json.chars() {
        match ch {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            _ => out.push(ch),
        }
    }
    out
}

/// Serialises compactly, the way `json.Marshal` does.
pub fn to_string<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    Ok(escape_like_go(&serde_json::to_string(value)?))
}

/// Serialises indented with two spaces and a trailing newline, the way
/// `json.NewEncoder(w)` with `SetIndent("", "  ")` and `Encode` does.
pub fn to_string_pretty<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let mut out = escape_like_go(&serde_json::to_string_pretty(value)?);
    out.push('\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize)]
    struct Sample {
        range: String,
        note: String,
    }

    #[test]
    fn escapes_the_characters_go_escapes() {
        let sample = Sample {
            range: ">=1.0.0 <2.0.0".to_string(),
            note: "a & b".to_string(),
        };
        assert_eq!(
            to_string(&sample).unwrap(),
            r#"{"range":"\u003e=1.0.0 \u003c2.0.0","note":"a \u0026 b"}"#
        );
    }

    #[test]
    fn leaves_documents_without_those_characters_untouched() {
        let sample = Sample {
            range: "^1.2.3".to_string(),
            note: "plain".to_string(),
        };
        assert_eq!(
            to_string(&sample).unwrap(),
            r#"{"range":"^1.2.3","note":"plain"}"#
        );
    }

    #[test]
    fn pretty_form_matches_two_space_indent_with_trailing_newline() {
        let sample = Sample {
            range: "<1".to_string(),
            note: "x".to_string(),
        };
        assert_eq!(
            to_string_pretty(&sample).unwrap(),
            "{\n  \"range\": \"\\u003c1\",\n  \"note\": \"x\"\n}\n"
        );
    }

    #[test]
    fn escapes_javascript_line_separators() {
        let sample = Sample {
            range: "a\u{2028}b".to_string(),
            note: "c\u{2029}d".to_string(),
        };
        let encoded = to_string(&sample).unwrap();
        assert!(encoded.contains("\\u2028") && encoded.contains("\\u2029"));
    }
}
