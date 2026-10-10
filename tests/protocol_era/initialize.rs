use rust_mcp_remote::protocol_era::{
    LATEST_PROTOCOL_VERSION, LegacyClientIdentity, SUPPORTED_PROTOCOL_VERSIONS,
    synthesize_initialize_result,
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

fn discover() -> Value {
    json!({ "supportedVersions": ["2026-07-28"], "capabilities": { "tools": {} } })
}

#[test]
fn the_client_is_told_its_own_protocol_version_not_the_remote_servers() {
    let result = synthesize_initialize_result(&discover(), &identity());

    assert_eq!(result["protocolVersion"], "2025-11-25");
    assert_eq!(result["capabilities"], json!({ "tools": {} }));
}

#[test]
fn a_client_asking_for_a_version_nobody_knows_is_answered_with_the_newest_legacy_one() {
    let identity = LegacyClientIdentity {
        protocol_version: Some("1999-01-01".to_string()),
        ..identity()
    };

    let result = synthesize_initialize_result(&discover(), &identity);

    assert_eq!(result["protocolVersion"], "2025-11-25");
}

#[test]
fn an_older_supported_version_is_kept() {
    let identity = LegacyClientIdentity {
        protocol_version: Some("2024-11-05".to_string()),
        ..identity()
    };

    let result = synthesize_initialize_result(&discover(), &identity);

    assert_eq!(result["protocolVersion"], "2024-11-05");
}

#[test]
fn a_client_with_no_version_is_answered_with_the_newest_legacy_one() {
    let result = synthesize_initialize_result(&discover(), &LegacyClientIdentity::default());

    assert_eq!(result["protocolVersion"], LATEST_PROTOCOL_VERSION);
}

#[test]
fn the_server_identifies_itself_through_the_metadata_it_advertised() {
    let mut discover = discover();
    discover["_meta"] =
        json!({ "io.modelcontextprotocol/serverInfo": { "name": "cipp", "version": "2.0.0" } });
    discover["instructions"] = json!("be careful");

    let result = synthesize_initialize_result(&discover, &identity());

    assert_eq!(
        result["serverInfo"],
        json!({ "name": "cipp", "version": "2.0.0" })
    );
    assert_eq!(result["instructions"], "be careful");
}

#[test]
fn a_server_without_a_name_is_given_a_placeholder_identity() {
    let mut discover = discover();
    discover["_meta"] =
        json!({ "io.modelcontextprotocol/serverInfo": { "name": "", "version": "2.0.0" } });

    let result = synthesize_initialize_result(&discover, &identity());

    assert_eq!(
        result["serverInfo"],
        json!({ "name": "remote MCP server", "version": "2026-07-28" })
    );
}

#[test]
fn empty_instructions_are_left_out() {
    let mut discover = discover();
    discover["instructions"] = json!("");

    let result = synthesize_initialize_result(&discover, &identity());

    assert_eq!(
        result,
        json!({
            "protocolVersion": "2025-11-25",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "remote MCP server", "version": "2026-07-28" }
        })
    );
}

#[test]
fn missing_capabilities_become_an_empty_object() {
    let result = synthesize_initialize_result(&json!({}), &identity());

    assert_eq!(result["capabilities"], json!({}));
}

#[test]
fn the_legacy_versions_match_the_sdk() {
    assert_eq!(LATEST_PROTOCOL_VERSION, "2025-11-25");
    assert_eq!(
        SUPPORTED_PROTOCOL_VERSIONS,
        [
            "2025-11-25",
            "2025-06-18",
            "2025-03-26",
            "2024-11-05",
            "2024-10-07"
        ]
    );
}
