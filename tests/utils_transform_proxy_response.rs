use rust_mcp_remote::utils::transform_proxy_response;
use serde_json::json;

fn ignored(patterns: &[&str]) -> Vec<String> {
    patterns.iter().map(|pattern| pattern.to_string()).collect()
}

#[test]
fn tools_list_drops_ignored_tools() {
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let response = json!({"jsonrpc": "2.0", "id": 1, "result": {
        "tools": [{"name": "readFile"}, {"name": "deleteFile"}],
        "nextCursor": "c"
    }});
    assert_eq!(
        transform_proxy_response(&ignored(&["delete*"]), false, &request, response),
        json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "readFile"}], "nextCursor": "c"}})
    );
}

#[test]
fn other_methods_are_not_filtered() {
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "resources/list"});
    let response =
        json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "deleteFile"}]}});
    assert_eq!(
        transform_proxy_response(&ignored(&["delete*"]), false, &request, response.clone()),
        response
    );
}

#[test]
fn tools_list_without_a_tool_array_is_unchanged() {
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    for response in [
        json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "nope"}}),
        json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
        json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": "x"}}),
    ] {
        assert_eq!(
            transform_proxy_response(&ignored(&["*"]), false, &request, response.clone()),
            response
        );
    }
}

#[test]
fn tool_without_a_name_is_tested_as_undefined() {
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let response = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{}, {"name": "a"}]}});
    assert_eq!(
        transform_proxy_response(&ignored(&["undef*"]), false, &request, response),
        json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "a"}]}})
    );
}

#[test]
fn modern_era_strips_complete_result_type_and_filters() {
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let response = json!({"jsonrpc": "2.0", "id": 1, "result": {
        "resultType": "complete",
        "tools": [{"name": "readFile"}, {"name": "deleteFile"}]
    }});
    assert_eq!(
        transform_proxy_response(&ignored(&["delete*"]), true, &request, response),
        json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "readFile"}]}})
    );
}

#[test]
fn modern_era_input_required_becomes_error() {
    let request = json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call"});
    let response = json!({"jsonrpc": "2.0", "id": 4, "result": {"resultType": "input_required"}});
    let transformed = transform_proxy_response(&[], true, &request, response);
    assert_eq!(transformed["id"], 4);
    assert_eq!(transformed["error"]["code"], -32603);
    assert!(transformed.get("result").is_none());
}

#[test]
fn legacy_era_keeps_result_type() {
    let request = json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call"});
    let response = json!({"jsonrpc": "2.0", "id": 4, "result": {"resultType": "input_required"}});
    assert_eq!(
        transform_proxy_response(&[], false, &request, response.clone()),
        response
    );
}
