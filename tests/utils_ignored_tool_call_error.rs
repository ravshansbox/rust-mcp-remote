use rust_mcp_remote::utils::ignored_tool_call_error;
use serde_json::json;

fn ignored(patterns: &[&str]) -> Vec<String> {
    patterns.iter().map(|pattern| pattern.to_string()).collect()
}

#[test]
fn call_to_ignored_tool_gets_error_response() {
    let request = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "deleteFile"}});
    assert_eq!(
        ignored_tool_call_error(&ignored(&["delete*"]), &request),
        Some(json!({
            "jsonrpc": "2.0",
            "id": 7,
            "error": {"code": -32603, "message": "Tool \"deleteFile\" is not available"}
        }))
    );
}

#[test]
fn call_to_allowed_tool_is_not_blocked() {
    let request =
        json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "readFile"}});
    assert_eq!(
        ignored_tool_call_error(&ignored(&["delete*"]), &request),
        None
    );
}

#[test]
fn other_methods_are_not_blocked() {
    let request = json!({"jsonrpc": "2.0", "id": 7, "method": "prompts/get", "params": {"name": "deleteFile"}});
    assert_eq!(
        ignored_tool_call_error(&ignored(&["delete*"]), &request),
        None
    );
}

#[test]
fn call_without_tool_name_is_not_blocked() {
    let request =
        json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": ""}});
    assert_eq!(ignored_tool_call_error(&ignored(&["*"]), &request), None);
    let request = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call"});
    assert_eq!(ignored_tool_call_error(&ignored(&["*"]), &request), None);
}

#[test]
fn error_keeps_string_id() {
    let request =
        json!({"jsonrpc": "2.0", "id": "abc", "method": "tools/call", "params": {"name": "x"}});
    assert_eq!(
        ignored_tool_call_error(&ignored(&["x"]), &request).unwrap()["id"],
        json!("abc")
    );
}
