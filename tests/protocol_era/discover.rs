use rust_mcp_remote::protocol_era::{
    FIRST_MODERN_PROTOCOL_VERSION, LegacyClientIdentity, RETIRED_SET_LOG_LEVEL,
    RETIRED_SUBSCRIBE_RESOURCE, RETIRED_UNSUBSCRIBE_RESOURCE, SUPPORTED_MODERN_VERSIONS,
    discover_request,
};
use serde_json::{Map, Value, json};

fn identity() -> LegacyClientIdentity {
    LegacyClientIdentity {
        protocol_version: Some("2025-11-25".to_string()),
        capabilities: Some(object(json!({ "roots": {} }))),
        client_info: Some(json!({ "name": "desktop-host", "version": "0.1.0" })),
    }
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => panic!("not an object"),
    }
}

#[test]
fn the_probe_itself_is_written_the_same_way_as_everything_after_it() {
    let request = discover_request("probe-1", &identity());

    assert_eq!(request["method"], "server/discover");
    assert_eq!(
        request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
        "2026-07-28"
    );
    assert_eq!(
        request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
        json!({ "roots": {} })
    );
}

#[test]
fn the_probe_is_a_jsonrpc_request_with_the_given_id() {
    let request = discover_request("probe-1", &LegacyClientIdentity::default());

    assert_eq!(
        request,
        json!({
            "jsonrpc": "2.0",
            "id": "probe-1",
            "method": "server/discover",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                }
            },
        })
    );
}

#[test]
fn the_first_modern_revision_is_the_only_one_this_proxy_speaks() {
    assert_eq!(FIRST_MODERN_PROTOCOL_VERSION, "2026-07-28");
    assert_eq!(SUPPORTED_MODERN_VERSIONS, ["2026-07-28"]);
}

#[test]
fn methods_retired_in_the_modern_era_are_named() {
    assert_eq!(RETIRED_SUBSCRIBE_RESOURCE, "resources/subscribe");
    assert_eq!(RETIRED_UNSUBSCRIBE_RESOURCE, "resources/unsubscribe");
    assert_eq!(RETIRED_SET_LOG_LEVEL, "logging/setLevel");
}
