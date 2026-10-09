use rust_mcp_remote::protocol_era::{
    LegacyClientIdentity, stamp_log_level, stamp_modern_meta, strip_subscription_meta,
    subscriptions_listen_request,
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
fn every_request_carries_the_version_and_capabilities_the_spec_makes_mandatory() {
    let stamped = stamp_modern_meta(
        &json!({ "method": "tools/list", "params": {} }),
        &identity(),
        "2026-07-28",
    );

    assert_eq!(
        stamped["params"]["_meta"],
        json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": { "roots": {} },
            "io.modelcontextprotocol/clientInfo": { "name": "desktop-host", "version": "0.1.0" },
        })
    );
    assert_eq!(stamped["method"], "tools/list");
}

#[test]
fn metadata_the_caller_already_set_is_left_alone() {
    let stamped = stamp_modern_meta(
        &json!({
            "method": "tools/call",
            "params": { "_meta": {
                "progressToken": "p1",
                "io.modelcontextprotocol/protocolVersion": "2025-01-01",
                "io.modelcontextprotocol/clientInfo": { "name": "other" },
            } },
        }),
        &identity(),
        "2026-07-28",
    );

    let meta = &stamped["params"]["_meta"];
    assert_eq!(meta["progressToken"], "p1");
    assert_eq!(
        meta["io.modelcontextprotocol/protocolVersion"],
        "2025-01-01"
    );
    assert_eq!(
        meta["io.modelcontextprotocol/clientInfo"],
        json!({ "name": "other" })
    );
}

#[test]
fn a_client_that_declared_no_capabilities_still_sends_the_field() {
    let stamped = stamp_modern_meta(
        &json!({ "method": "tools/list", "params": {} }),
        &LegacyClientIdentity {
            protocol_version: Some("2025-11-25".to_string()),
            ..Default::default()
        },
        "2026-07-28",
    );

    let meta = stamped["params"]["_meta"].as_object().unwrap();
    assert_eq!(
        meta["io.modelcontextprotocol/clientCapabilities"],
        json!({})
    );
    assert!(!meta.contains_key("io.modelcontextprotocol/clientInfo"));
}

#[test]
fn a_request_without_params_gains_params_with_meta() {
    let stamped = stamp_modern_meta(&json!({ "method": "ping" }), &identity(), "2026-07-28");

    assert_eq!(
        stamped["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
        "2026-07-28"
    );
}

#[test]
fn a_requested_log_level_is_stamped_next_to_existing_meta() {
    let stamped = stamp_log_level(
        json!({ "method": "tools/list", "params": { "cursor": "c", "_meta": { "progressToken": "p1" } } }),
        Some("debug"),
    );

    assert_eq!(
        stamped["params"],
        json!({ "cursor": "c", "_meta": { "progressToken": "p1", "io.modelcontextprotocol/logLevel": "debug" } })
    );
}

#[test]
fn no_log_level_leaves_the_message_unchanged() {
    let message = json!({ "method": "tools/list" });

    assert_eq!(stamp_log_level(message.clone(), None), message);
    assert_eq!(stamp_log_level(message.clone(), Some("")), message);
}

#[test]
fn the_listen_request_is_a_stamped_modern_request() {
    let request = subscriptions_listen_request(
        "listen-1",
        &identity(),
        "2026-07-28",
        &object(json!({ "toolsListChanged": true })),
    );

    assert_eq!(request["jsonrpc"], "2.0");
    assert_eq!(request["id"], "listen-1");
    assert_eq!(request["method"], "subscriptions/listen");
    assert_eq!(
        request["params"]["notifications"],
        json!({ "toolsListChanged": true })
    );
    assert_eq!(
        request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
        "2026-07-28"
    );
}

#[test]
fn the_subscription_id_is_stripped_and_empty_meta_removed() {
    let stripped = strip_subscription_meta(json!({
        "method": "notifications/tools/list_changed",
        "params": { "_meta": { "io.modelcontextprotocol/subscriptionId": "sub-1" } },
    }));

    assert_eq!(stripped["method"], "notifications/tools/list_changed");
    assert_eq!(stripped["params"], json!({}));
}

#[test]
fn other_meta_survives_stripping_in_its_original_order() {
    let stripped = strip_subscription_meta(json!({
        "method": "notifications/resources/updated",
        "params": {
            "uri": "file:///a",
            "_meta": { "a": 1, "io.modelcontextprotocol/subscriptionId": "sub-1", "b": 2, "c": 3 },
        },
    }));

    let meta = stripped["params"]["_meta"].as_object().unwrap();
    assert_eq!(meta.keys().collect::<Vec<_>>(), ["a", "b", "c"]);
    assert_eq!(stripped["params"]["uri"], "file:///a");
}

#[test]
fn a_notification_without_a_subscription_id_is_unchanged() {
    let message = json!({ "method": "notifications/message", "params": { "_meta": { "a": 1 } } });

    assert_eq!(strip_subscription_meta(message.clone()), message);
}
