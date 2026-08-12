//! `extract_ips` — the tool that takes a document rather than a path.
//!
//! It touches no filesystem. An agent already has file-read tools;
//! duplicating them here would add a path-traversal surface for no
//! capability. The tool that needs a filesystem is `ips_le_scan`.
//!
//! `fixtures/mcp-extract-ips.json` pins its answers case by case, so a
//! change to the envelope or to any refusal fails a test rather than a
//! caller.

use serde_json::{Value, json};

use crate::extract::{self, Class, Kind, SUPPORTED_FORMATS, resolve_format};

const DEFAULT_MAX_RESULTS: usize = 500;
const MAX_MAX_RESULTS: usize = 5000;

pub(crate) fn definition() -> Value {
    json!({
        "name": "extract_ips",
        "description": "Extract every IP address, CIDR block and MAC address from a document, \
                        normalized and classified. IPv6 is canonicalized per RFC 5952, so \
                        2001:0db8::0001 and 2001:db8::1 come back as one address rather than \
                        two. Each finding carries its line, column and — for JSON, YAML, TOML, \
                        INI, dotenv, CSV and logs — the key it sits under. Text this cannot read \
                        unambiguously is returned as a named refusal, never as a guess: a \
                        leading zero (octal or decimal, depending on the resolver), a dotted \
                        triple that may be a version, a bare integer in an address field. \
                        Resolves no names, geolocates nothing, opens no sockets.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": { "type": "string", "description": "The document text to scan." },
                "format": {
                    "type": "string",
                    "enum": SUPPORTED_FORMATS,
                    "description": "Document format. Optional — it only decides whether findings \
                                    carry a key path, never whether they are found.",
                },
                "filename": {
                    "type": "string",
                    "description": "Filename used to infer the format when `format` is absent, \
                                    e.g. \"app.yaml\" or \"access.log\".",
                },
                "kind": {
                    "type": "array",
                    "items": { "type": "string", "enum": Kind::ALL },
                    "description": "Report only these kinds. Refusals are always reported.",
                },
                "class": {
                    "type": "array",
                    "items": { "type": "string", "enum": Class::ALL },
                    "description": "Report only these classes. Refusals are always reported.",
                },
                "maxResults": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_MAX_RESULTS,
                    "default": DEFAULT_MAX_RESULTS,
                    "description": format!(
                        "Cap on returned findings (default {DEFAULT_MAX_RESULTS}). \
                         meta.truncated reports whether any were dropped."
                    ),
                },
            },
            "required": ["content"],
            "additionalProperties": false,
        },
    })
}

pub(crate) fn run(arguments: &Value) -> Result<Value, String> {
    let content = arguments
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| "content is required and must be a string".to_string())?;
    let max_results = read_max_results(arguments)?;
    let kinds = filter(arguments, "kind", Kind::parse, &Kind::ALL)?;
    let classes = filter(arguments, "class", Class::parse, &Class::ALL)?;

    // Never a refusal. An agent that knows nothing about a document
    // still gets its addresses — the format only decides whether they
    // carry a key path.
    let format = resolve_format(
        arguments.get("format").and_then(Value::as_str),
        arguments.get("filename").and_then(Value::as_str),
    );

    // A parse failure costs the key paths and nothing else, so it is a
    // warning on a successful envelope rather than an error. Saying
    // `ok: false` here would have a model conclude the document held no
    // addresses, when what it held was a broken config full of them.
    let diagnostics: Vec<Value> = extract::parse_error(content, format)
        .map(|message| json!({ "severity": "warning", "code": "unparsed", "message": message }))
        .into_iter()
        .collect();

    // The same rule the CLI filters by, from the same place: a refusal
    // survives every filter it cannot be judged by, and a second copy of
    // that here would be a second chance to lose one.
    let mut found: Vec<Value> = extract::find(content, format)
        .into_iter()
        .filter(|one| one.survives(&kinds, &classes))
        .map(|one| serde_json::to_value(one).expect("a finding serializes"))
        .collect();

    // The `truncated` flag matters more than the cap: a silently
    // incomplete answer is wrong in the most expensive way, and this is
    // a tool an agent will use to decide whether a list is complete.
    let truncated = found.len() > max_results;
    found.truncate(max_results);

    let refused = found.iter().filter(|one| !one["refused"].is_null()).count();
    let count = found.len();
    Ok(super::envelope(
        "extract_ips",
        &json!({
            "addresses": found,
            "refused": refused,
            "format": format,
        }),
        count,
        &diagnostics,
        truncated,
    ))
}

/// Read an optional array-of-names filter.
///
/// A name nobody recognises is an error and never a silent
/// pass-through: an agent that asked for `private` and got everything
/// would report a private address that is not one.
pub(crate) fn filter<T>(
    arguments: &Value,
    name: &str,
    parse: fn(&str) -> Option<T>,
    allowed: &[&str],
) -> Result<Vec<T>, String> {
    let allowed = allowed.join(", ");
    let Some(value) = arguments.get(name) else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .ok_or_else(|| format!("{name} must be an array of names"))?;
    items
        .iter()
        .map(|item| {
            let text = item
                .as_str()
                .ok_or_else(|| format!("{name} must be an array of names"))?;
            parse(&text.to_lowercase()).ok_or_else(|| format!("{text} is not a {name}: {allowed}"))
        })
        .collect()
}

/// Clamp quietly, reject loudly.
fn read_max_results(arguments: &Value) -> Result<usize, String> {
    let Some(raw) = arguments.get("maxResults") else {
        return Ok(DEFAULT_MAX_RESULTS);
    };
    let invalid = "maxResults must be a positive integer".to_string();
    let value = raw.as_u64().ok_or(invalid.clone())?;
    if value < 1 {
        return Err(invalid);
    }
    Ok(usize::try_from(value)
        .unwrap_or(MAX_MAX_RESULTS)
        .min(MAX_MAX_RESULTS))
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;
    use crate::extract::FALLBACK_FORMAT;
    use crate::extract::corpus::document;

    const CASES: &str = include_str!("../../fixtures/mcp-extract-ips.json");

    #[derive(Debug, Deserialize)]
    struct Case {
        name: String,
        file: Option<String>,
        arguments: Value,
        expected: Option<Value>,
        #[serde(rename = "expectedError")]
        expected_error: Option<String>,
    }

    #[test]
    fn every_pinned_case_answers_identically() {
        let cases: Vec<Case> = serde_json::from_str(CASES).expect("the corpus is valid JSON");
        assert!(!cases.is_empty(), "the corpus is empty");

        for case in cases {
            let mut arguments = case.arguments.clone();
            if let Some(file) = case.file.as_deref() {
                arguments["content"] = json!(document(file));
            }
            match (case.expected, case.expected_error) {
                (_, Some(expected)) => {
                    assert_eq!(
                        run(&arguments).expect_err(&case.name),
                        expected,
                        "{}",
                        case.name
                    );
                }
                (Some(expected), None) => {
                    assert_eq!(
                        run(&arguments).expect(&case.name),
                        expected,
                        "{}",
                        case.name
                    );
                }
                (None, None) => panic!("{} pins neither a result nor an error", case.name),
            }
        }
    }

    #[test]
    fn the_tool_name_is_pinned() {
        assert_eq!(definition()["name"], "extract_ips");
    }

    /// An enum the schema advertises but the parser rejects is a
    /// promise the tool breaks on the first call that believes it.
    #[test]
    fn the_advertised_enums_match_what_resolves() {
        let definition = definition();
        let properties = &definition["inputSchema"]["properties"];
        let names = |value: &Value| -> Vec<String> {
            value
                .as_array()
                .expect("an enum")
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        };
        assert_eq!(names(&properties["format"]["enum"]), SUPPORTED_FORMATS);
        assert_eq!(names(&properties["kind"]["items"]["enum"]), Kind::ALL);
        assert_eq!(names(&properties["class"]["items"]["enum"]), Class::ALL);
    }

    /// The tool reaches no filesystem — the property that lets an agent
    /// call it anywhere, and it must not regress.
    #[test]
    fn the_tool_needs_no_filesystem() {
        let result = run(&json!({ "content": "connect 10.0.0.1" })).expect("a result");
        assert_eq!(result["data"]["addresses"][0]["normalized"], "10.0.0.1");
        assert!(result["data"].get("exists").is_none());
    }

    /// An unresolved format is a scan without key paths, never a
    /// refusal.
    #[test]
    fn an_unknown_format_falls_back_rather_than_failing() {
        let result =
            run(&json!({ "content": "bind 2001:db8::1", "format": "nonsense" })).expect("a result");
        assert_eq!(result["data"]["format"], FALLBACK_FORMAT);
        assert_eq!(result["data"]["addresses"][0]["normalized"], "2001:db8::1");
        assert_eq!(result["data"]["addresses"][0]["key"], Value::Null);
    }

    /// An empty answer is the scan running and finding nothing.
    #[test]
    fn a_document_with_no_addresses_is_an_ordinary_result() {
        let result = run(&json!({ "content": "no addresses here" })).expect("a result");
        assert_eq!(result["ok"], true);
        assert_eq!(result["meta"]["count"], 0);
    }

    /// A broken document keeps its addresses and loses its key paths,
    /// and the envelope is still successful — the scan ran.
    #[test]
    fn a_broken_document_still_reports_its_addresses() {
        let result =
            run(&json!({ "content": "{not json 10.0.0.5", "format": "json" })).expect("a result");
        assert_eq!(result["ok"], true);
        assert_eq!(result["diagnostics"][0]["code"], "unparsed");
        assert_eq!(result["data"]["addresses"][0]["text"], "10.0.0.5");
    }

    #[test]
    fn a_filter_narrows_the_answer_and_never_hides_a_refusal() {
        let content = "8.8.8.8 10.0.0.1 010.1.1.1";
        let result = run(&json!({ "content": content, "class": ["global"] })).expect("a result");
        let texts: Vec<&str> = result["data"]["addresses"]
            .as_array()
            .expect("an array")
            .iter()
            .filter_map(|one| one["text"].as_str())
            .collect();
        assert_eq!(texts, ["8.8.8.8", "010.1.1.1"]);
        assert_eq!(result["data"]["refused"], 1);
    }

    #[test]
    fn an_unknown_filter_name_is_refused() {
        let error = run(&json!({ "content": "x", "kind": ["ipv5"] })).expect_err("a refusal");
        assert!(error.contains("ipv4"), "{error}");
    }

    #[test]
    fn a_fractional_cap_is_refused() {
        let error = run(&json!({ "content": "x", "maxResults": 1.5 })).expect_err("a refusal");
        assert_eq!(error, "maxResults must be a positive integer");
    }

    #[test]
    fn a_truncated_answer_says_so() {
        let content = (0..10)
            .map(|n| format!("10.0.0.{n}"))
            .collect::<Vec<String>>()
            .join(" ");
        let result = run(&json!({ "content": content, "maxResults": 3 })).expect("a result");
        assert_eq!(result["meta"]["count"], 3);
        assert_eq!(result["meta"]["truncated"], true);
    }
}
