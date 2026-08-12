//! The agent surface: the same extraction over the Model Context
//! Protocol on stdio, so a model can ask what addresses are in a
//! document rather than be handed the text and pattern-match it itself.
//!
//! That difference is the point here more than in any sibling. A model
//! reading `2001:0db8::0001` and `2001:db8::1` out of a diff will
//! usually call them two addresses, and reading `010.1.1.1` will
//! usually call it 10.1.1.1. This surface exists so it does not have to
//! guess — and so that when the answer is unknowable, what comes back
//! is a named refusal instead of a confident sentence.
//!
//! Two rules the family's MCP surfaces established:
//!
//! - **An empty answer is not an error.** A document with no addresses
//!   comes back as an ordinary result carrying `ok: true` — the scan
//!   ran. Only a malformed question is a protocol error.
//! - **Refusals speak the caller's vocabulary.** An MCP caller has no
//!   command line, so no message here mentions a flag.
//!
//! Read-only by construction: nothing on this surface writes, and
//! nothing on it reaches a network.

pub(crate) mod extract;

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use serde_json::{Value, json};

use crate::extract::{Class, Kind, resolve_format};
use crate::scan::{self, ScanOptions};
use crate::walk::WalkOptions;

const PROTOCOL_VERSION: &str = "2025-06-18";

/// JSON-RPC error codes, from the spec.
const INVALID_PARAMS: i64 = -32602;
const METHOD_NOT_FOUND: i64 = -32601;

pub(crate) fn serve() -> ExitCode {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else {
            return ExitCode::from(2);
        };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(request) = serde_json::from_str::<Value>(&line) else {
            // A frame that is not JSON has no id to answer against;
            // dropping it is the only honest option.
            continue;
        };
        let Some(response) = handle(&request) else {
            continue; // a notification: no reply
        };
        if writeln!(stdout, "{response}").is_err() || stdout.flush().is_err() {
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}

fn handle(request: &Value) -> Option<Value> {
    let id = request.get("id").cloned();
    let method = request.get("method")?.as_str()?;
    // Notifications carry no id and get no reply.
    id.as_ref()?;

    let result = match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "ips-le", "version": env!("CARGO_PKG_VERSION") },
        })),
        "tools/list" => Ok(json!({ "tools": tool_definitions() })),
        "tools/call" => call_tool(request.get("params")),
        "ping" => Ok(json!({})),
        other => Err((
            METHOD_NOT_FOUND,
            format!("this server does not implement {other}"),
        )),
    };

    Some(match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err((code, message)) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": code, "message": message },
        }),
    })
}

fn tool_definitions() -> Value {
    json!([
        extract::definition(),
        {
            "name": "ips_le_scan",
            "description": "Find every IP address, CIDR block and MAC address in files or \
                            directories, with the file it came from, its line and column, and \
                            the key it sits under where the format has one. Reads the \
                            filesystem; never writes to it, never resolves a name and never \
                            opens a socket.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "a file or directory to read" },
                    "paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "several files or directories, instead of `path`",
                    },
                    "format": {
                        "type": "string",
                        "description": "Force a format for every file instead of inferring one \
                                        per file name. An unrecognised name still scans; it just \
                                        reports no key paths.",
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
                    "hidden": {
                        "type": "boolean",
                        "default": false,
                        "description": "Walk hidden files and directories too.",
                    },
                    "ignored": {
                        "type": "boolean",
                        "default": false,
                        "description": "Walk files excluded by .gitignore too.",
                    },
                },
            },
        },
    ])
}

/// Protocol failures (no tool named, an unknown tool) are JSON-RPC
/// errors; a tool that fails on its arguments returns a result carrying
/// `isError`, so a model reads the reason and reacts rather than
/// concluding the server is broken.
fn call_tool(params: Option<&Value>) -> Result<Value, (i64, String)> {
    let params = params.ok_or((INVALID_PARAMS, "no tool call was supplied".to_string()))?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or((INVALID_PARAMS, "the tool call named no tool".to_string()))?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    match name {
        "extract_ips" => Ok(match extract::run(&arguments) {
            Ok(result) => tool_result(&result),
            Err(message) => tool_failure(&message),
        }),
        "ips_le_scan" => Ok(match scan_tool(&arguments) {
            Ok(result) => tool_result(&result),
            Err(message) => tool_failure(&message),
        }),
        other => Err((
            INVALID_PARAMS,
            format!("this server offers no tool named {other}"),
        )),
    }
}

fn scan_tool(arguments: &Value) -> Result<Value, String> {
    let inputs = requested_paths(arguments)?;
    let flag = |name: &str| {
        arguments
            .get(name)
            .and_then(Value::as_bool)
            .unwrap_or(false)
    };
    let walk_options = WalkOptions {
        hidden: flag("hidden"),
        respect_ignore: !flag("ignored"),
    };
    let options = ScanOptions {
        format: arguments
            .get("format")
            .and_then(Value::as_str)
            .map(|name| resolve_format(Some(name), None)),
        kinds: extract::filter(arguments, "kind", Kind::parse, &Kind::ALL)?,
        classes: extract::filter(arguments, "class", Class::parse, &Class::ALL)?,
    };

    // A binary file was never a text candidate, so it gets no report —
    // but the count is carried, because an agent reading `reports` as
    // the whole tree would otherwise be wrong about coverage.
    let (read, binary) = scan::tree(&inputs, &walk_options, &options)?;
    let reports: Vec<Value> = read
        .iter()
        .map(|report| serde_json::to_value(report).expect("a report serializes"))
        .collect();

    let addresses: usize = read.iter().map(|report| report.summary.addresses).sum();
    let refused: usize = read.iter().map(|report| report.summary.refused).sum();

    let mut diagnostics: Vec<Value> = read
        .iter()
        .filter(|report| report.was_skipped())
        .map(|report| {
            warning(
                "unreadable",
                &format!(
                    "{} could not be read, so this scan does not cover it",
                    report.file
                ),
            )
        })
        .collect();
    if refused > 0 {
        // A model treating `addresses` as the whole answer has to know
        // how much of the document this declined to name — otherwise
        // the refusal design buys nothing on the surface that needs it
        // most.
        diagnostics.push(warning(
            "refused",
            &format!("{refused} candidates could not be read unambiguously and were refused"),
        ));
    }

    let count = reports.len();
    Ok(envelope(
        "ips_le_scan",
        &json!({
            "reports": reports,
            "addresses": addresses,
            "refused": refused,
            "binaryFiles": binary,
        }),
        count,
        &diagnostics,
        false,
    ))
}

fn requested_paths(arguments: &Value) -> Result<Vec<PathBuf>, String> {
    if let Some(path) = arguments.get("path").and_then(Value::as_str) {
        return Ok(vec![PathBuf::from(path)]);
    }
    if let Some(items) = arguments.get("paths").and_then(Value::as_array) {
        let paths: Vec<PathBuf> = items
            .iter()
            .filter_map(|item| item.as_str().map(PathBuf::from))
            .collect();
        if paths.is_empty() {
            return Err("the list of paths was empty".to_string());
        }
        return Ok(paths);
    }
    Err("no file or directory was supplied to read".to_string())
}

/// The one result shape every tool returns: `{ ok, data, diagnostics,
/// meta }`.
///
/// **`ok` reports whether the check ran, not whether the answer is
/// yes.** A document full of refusals is the answer, not a failure to
/// produce one — conflating the two would have a model report a broken
/// tool when what it actually learned is that the addresses are
/// ambiguous.
pub(crate) fn envelope(
    tool: &str,
    data: &Value,
    count: usize,
    diagnostics: &[Value],
    truncated: bool,
) -> Value {
    let ok = !diagnostics
        .iter()
        .any(|diagnostic| diagnostic["severity"].as_str() == Some("error"));
    json!({
        "ok": ok,
        "data": data,
        "diagnostics": diagnostics,
        "meta": { "tool": tool, "count": count, "truncated": truncated },
    })
}

/// An MCP tool result: the envelope as text (what a model reads) and
/// the same envelope structured.
fn tool_result(envelope: &Value) -> Value {
    let text = serde_json::to_string_pretty(envelope).expect("an envelope serializes");
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": envelope,
        "isError": false,
    })
}

fn warning(code: &str, message: &str) -> Value {
    json!({ "severity": "warning", "code": code, "message": message })
}

/// The tool could not run on the arguments given. `isError` so a model
/// reads the message and corrects itself.
fn tool_failure(message: &str) -> Value {
    json!({
        "content": [{ "type": "text", "text": message }],
        "isError": true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TempTree;

    fn request(method: &str, params: &Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
    }

    fn call(name: &str, arguments: &Value) -> Value {
        handle(&request(
            "tools/call",
            &json!({ "name": name, "arguments": arguments }),
        ))
        .expect("a reply")
    }

    #[test]
    fn initialize_answers_with_the_protocol_version() {
        let response = handle(&request("initialize", &json!({}))).expect("a reply");
        assert_eq!(response["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(response["result"]["serverInfo"]["name"], "ips-le");
    }

    #[test]
    fn tools_list_offers_both_tools() {
        let response = handle(&request("tools/list", &json!({}))).expect("a reply");
        let tools = response["result"]["tools"].as_array().expect("tools");
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert_eq!(names, ["extract_ips", "ips_le_scan"]);
    }

    #[test]
    fn a_notification_gets_no_reply() {
        let notification = json!({ "jsonrpc": "2.0", "method": "initialized" });
        assert!(handle(&notification).is_none());
    }

    #[test]
    fn an_unknown_method_or_tool_is_a_protocol_error() {
        let response = handle(&request("does/not/exist", &json!({}))).expect("a reply");
        assert_eq!(response["error"]["code"], METHOD_NOT_FOUND);
        let response = call("ips_le_resolve", &json!({}));
        assert_eq!(response["error"]["code"], INVALID_PARAMS);
    }

    /// A bad argument is the tool failing on what it was given, not the
    /// server breaking — so it comes back as a result carrying isError.
    #[test]
    fn a_missing_argument_is_a_tool_failure_not_a_protocol_error() {
        let response = call("ips_le_scan", &json!({}));
        assert!(response.get("error").is_none(), "{response}");
        assert_eq!(response["result"]["isError"], true);
        assert!(
            response["result"]["content"][0]["text"]
                .as_str()
                .expect("a message")
                .contains("no file or directory")
        );
    }

    #[test]
    fn the_scan_tool_reports_what_it_found() {
        let tree = TempTree::new("mcp-scan");
        tree.write("app.yaml", "server:\n  bind: 10.0.0.5\n");
        let response = call(
            "ips_le_scan",
            &json!({ "path": tree.path().to_string_lossy() }),
        );
        let envelope = &response["result"]["structuredContent"];
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(envelope["ok"], true);
        assert_eq!(envelope["data"]["addresses"], 1);
        let found = &envelope["data"]["reports"][0]["addresses"][0];
        assert_eq!(found["normalized"], "10.0.0.5");
        assert_eq!(found["key"], "server.bind");
        assert_eq!(found["line"], 2);
    }

    /// A refusal is never silent on this surface: an agent reading only
    /// `addresses` has to be told the rest of the story.
    #[test]
    fn the_scan_tool_carries_refusals_and_says_so() {
        let tree = TempTree::new("mcp-refused");
        tree.write("hosts.env", "BIND_IP=010.1.1.1\n");
        let response = call(
            "ips_le_scan",
            &json!({ "path": tree.path().to_string_lossy() }),
        );
        let envelope = &response["result"]["structuredContent"];
        assert_eq!(envelope["ok"], true, "the scan ran");
        assert_eq!(envelope["data"]["addresses"], 0);
        assert_eq!(envelope["data"]["refused"], 1);
        assert_eq!(envelope["diagnostics"][0]["code"], "refused");
    }

    #[test]
    fn the_scan_tool_filters_on_request() {
        let tree = TempTree::new("mcp-filter");
        tree.write("a.txt", "10.0.0.1 and 8.8.8.8\n");
        let path = tree.path().to_string_lossy().to_string();
        let all = call("ips_le_scan", &json!({ "path": path }));
        assert_eq!(all["result"]["structuredContent"]["data"]["addresses"], 2);
        let global = call("ips_le_scan", &json!({ "path": path, "class": ["global"] }));
        assert_eq!(
            global["result"]["structuredContent"]["data"]["addresses"],
            1
        );
    }

    #[test]
    fn an_unknown_filter_name_is_a_tool_failure() {
        let tree = TempTree::new("mcp-badfilter");
        tree.write("a.txt", "10.0.0.1\n");
        let response = call(
            "ips_le_scan",
            &json!({ "path": tree.path().to_string_lossy(), "kind": ["ipv5"] }),
        );
        assert_eq!(response["result"]["isError"], true);
    }

    /// Refusals speak the caller's vocabulary: an MCP caller has no
    /// command line, so no message may name a flag.
    #[test]
    fn no_message_mentions_a_command_line_flag() {
        let definitions = serde_json::to_string(&tool_definitions()).expect("serializes");
        assert!(!definitions.contains("--"), "{definitions}");

        let tree = TempTree::new("mcp-vocabulary");
        tree.write("a.json", "{\"a\":\"10.0.0.1\"}\n");
        for arguments in [
            json!({}),
            json!({ "paths": [] }),
            json!({ "path": "/no/such/place-xyz" }),
            json!({ "path": tree.path().to_string_lossy(), "kind": ["ipv5"] }),
        ] {
            let rendered =
                serde_json::to_string(&call("ips_le_scan", &arguments)).expect("serializes");
            assert!(!rendered.contains("--"), "{rendered}");
        }
    }

    /// Every tool returns the same envelope, so a caller writes one
    /// reader for all of them.
    #[test]
    fn every_tool_returns_the_same_envelope_shape() {
        let tree = TempTree::new("mcp-envelope");
        tree.write("a.md", "x");
        let results = [
            call("extract_ips", &json!({ "content": "10.0.0.1" })),
            call(
                "ips_le_scan",
                &json!({ "path": tree.path().to_string_lossy() }),
            ),
        ];
        for result in results {
            let envelope = &result["result"]["structuredContent"];
            assert!(envelope["ok"].is_boolean(), "{envelope}");
            assert!(!envelope["data"].is_null(), "{envelope}");
            assert!(envelope["diagnostics"].is_array(), "{envelope}");
            assert!(envelope["meta"]["tool"].is_string(), "{envelope}");
            assert!(envelope["meta"]["count"].is_number(), "{envelope}");
            assert!(envelope["meta"]["truncated"].is_boolean(), "{envelope}");
        }
    }
}
