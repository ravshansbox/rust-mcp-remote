use rust_mcp_remote::utils::{MirroredMcpHeaders, mcp_headers_from_body};

fn mirrored(method: &str, name: Option<&str>) -> Option<MirroredMcpHeaders> {
    Some(MirroredMcpHeaders {
        method: method.to_string(),
        name: name.map(str::to_string),
    })
}

#[test]
fn mirrors_the_method_of_a_request() {
    assert_eq!(
        mcp_headers_from_body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#),
        mirrored("initialize", None)
    );
    assert_eq!(
        mcp_headers_from_body(r#"{"jsonrpc":"2.0","method":"server/discover","params":{}}"#),
        mirrored("server/discover", None)
    );
}

#[test]
fn tools_call_and_prompts_get_carry_params_name() {
    assert_eq!(
        mcp_headers_from_body(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_weather","arguments":{"location":"Seattle, WA"}}}"#
        ),
        mirrored("tools/call", Some("get_weather"))
    );
    assert_eq!(
        mcp_headers_from_body(
            r#"{"jsonrpc":"2.0","method":"prompts/get","params":{"name":"summarize"}}"#
        ),
        mirrored("prompts/get", Some("summarize"))
    );
}

#[test]
fn resources_read_takes_its_name_from_params_uri() {
    assert_eq!(
        mcp_headers_from_body(
            r#"{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///projects/世界.json","name":"ignored"}}"#
        ),
        mirrored("resources/read", Some("file:///projects/世界.json"))
    );
}

#[test]
fn a_method_without_a_name_source_does_not_invent_one() {
    assert_eq!(
        mcp_headers_from_body(r#"{"method":"tools/list","params":{"name":"x","uri":"y"}}"#),
        mirrored("tools/list", None)
    );
}

#[test]
fn a_missing_or_unusable_name_sends_the_method_alone() {
    for body in [
        r#"{"method":"tools/call"}"#,
        r#"{"method":"tools/call","params":null}"#,
        r#"{"method":"tools/call","params":"get_weather"}"#,
        r#"{"method":"tools/call","params":["get_weather"]}"#,
        r#"{"method":"tools/call","params":{}}"#,
        r#"{"method":"tools/call","params":{"name":""}}"#,
        r#"{"method":"tools/call","params":{"name":42}}"#,
        r#"{"method":"resources/read","params":{"name":"file:///a"}}"#,
    ] {
        assert_eq!(
            mcp_headers_from_body(body),
            mirrored(body_method(body), None),
            "{body}"
        );
    }
}

fn body_method(body: &str) -> &'static str {
    if body.contains("resources/read") {
        "resources/read"
    } else {
        "tools/call"
    }
}

#[test]
fn nothing_is_mirrored_without_a_single_method() {
    for body in [
        "",
        "not json",
        "null",
        "42",
        r#""tools/call""#,
        r#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
        r#"{"method":""}"#,
        r#"{"method":7}"#,
    ] {
        assert_eq!(mcp_headers_from_body(body), None, "{body}");
    }
}

#[test]
fn the_last_duplicate_key_wins_as_in_json_parse() {
    assert_eq!(
        mcp_headers_from_body(
            r#"{"method":"tools/list","method":"tools/call","params":{"name":"a","name":"b"}}"#
        ),
        mirrored("tools/call", Some("b"))
    );
}
