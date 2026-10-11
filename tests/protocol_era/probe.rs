use rust_mcp_remote::protocol_era::{ProbeVerdict, classify_probe_error, classify_probe_response};
use serde_json::{Value, json};

fn discover() -> Value {
    json!({ "supportedVersions": ["2025-11-25", "2026-07-28"], "capabilities": { "tools": {} } })
}

#[test]
fn a_discover_result_offering_a_modern_version_is_modern() {
    let verdict = classify_probe_response(&json!({ "result": discover() }), "2026-07-28");

    assert_eq!(
        verdict,
        ProbeVerdict::Modern {
            version: "2026-07-28".to_string(),
            discover: discover(),
        }
    );
}

#[test]
fn a_result_that_is_not_a_discover_result_or_offers_no_modern_version_is_legacy() {
    for result in [
        json!({ "result": {} }),
        json!({ "result": { "supportedVersions": ["2026-07-28"] } }),
        json!({ "result": { "supportedVersions": "2026-07-28", "capabilities": {} } }),
        json!({ "result": { "supportedVersions": ["2025-11-25"], "capabilities": {} } }),
        json!({}),
    ] {
        assert_eq!(
            classify_probe_response(&result, "2026-07-28"),
            ProbeVerdict::Legacy,
            "{result}"
        );
    }
}

#[test]
fn an_error_response_is_classified_by_its_error_object() {
    let message = json!({ "error": { "code": -32601, "message": "Method not found" } });

    assert_eq!(
        classify_probe_response(&message, "2026-07-28"),
        ProbeVerdict::Legacy
    );
}

#[test]
fn an_error_other_than_unsupported_version_is_legacy() {
    for error in [
        json!({ "code": -32601 }),
        json!({ "code": -32602, "data": { "supported": ["2026-07-28"] } }),
        json!({}),
    ] {
        assert_eq!(
            classify_probe_error(&error, "2026-07-28"),
            ProbeVerdict::Legacy,
            "{error}"
        );
    }
}

#[test]
fn an_unsupported_version_error_without_a_usable_version_list_is_legacy() {
    for data in [
        Value::Null,
        json!({}),
        json!({ "supported": [] }),
        json!({ "supported": [7] }),
        json!({ "supported": ["2025-06-18", "2025-11-25"] }),
    ] {
        let error = json!({ "code": -32022, "data": data });
        assert_eq!(
            classify_probe_error(&error, "2026-07-28"),
            ProbeVerdict::Legacy,
            "{error}"
        );
    }
}

#[test]
fn an_unsupported_version_error_naming_a_version_this_proxy_speaks_asks_again() {
    let error = json!({ "code": -32022, "data": { "supported": ["2025-11-25", "2026-07-28"] } });

    assert_eq!(
        classify_probe_error(&error, "2027-01-01"),
        ProbeVerdict::Corrective {
            version: "2026-07-28".to_string()
        }
    );
}

#[test]
fn an_unsupported_version_error_naming_only_unknown_modern_versions_is_an_error() {
    let with_message = json!({
        "code": -32022,
        "message": "Unsupported protocol version",
        "data": { "supported": ["2027-01-01"] },
    });
    let without_message = json!({
        "code": -32022,
        "data": { "supported": ["2027-01-01"], "requested": "2026-12-01" },
    });
    let without_requested = json!({ "code": -32022, "data": { "supported": ["2027-01-01"] } });

    assert_eq!(
        classify_probe_error(&with_message, "2026-07-28"),
        ProbeVerdict::Error("MCP error -32022: Unsupported protocol version".to_string())
    );
    assert_eq!(
        classify_probe_error(&without_message, "2026-07-28"),
        ProbeVerdict::Error(
            "MCP error -32022: Unsupported protocol version: 2026-12-01".to_string()
        )
    );
    assert_eq!(
        classify_probe_error(&without_requested, "2026-07-28"),
        ProbeVerdict::Error(
            "MCP error -32022: Unsupported protocol version: 2026-07-28".to_string()
        )
    );
}
