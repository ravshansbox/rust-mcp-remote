use rust_mcp_remote::protocol_era::{EraVerdict, read_era_from_discover_response};
use serde_json::{Value, json};

fn discover() -> Value {
    json!({ "supportedVersions": ["2026-07-28"], "capabilities": { "tools": {} } })
}

fn reason(verdict: EraVerdict) -> String {
    match verdict {
        EraVerdict::Legacy { reason } | EraVerdict::Incompatible { reason } => reason,
        EraVerdict::Modern { .. } => panic!("expected a reason"),
    }
}

#[test]
fn a_discover_result_is_a_modern_server() {
    let verdict = read_era_from_discover_response(&json!({ "result": discover() }));

    assert_eq!(
        verdict,
        EraVerdict::Modern {
            version: "2026-07-28".to_string(),
            discover: discover(),
        }
    );
}

#[test]
fn an_unknown_method_is_a_server_still_expecting_a_handshake() {
    let verdict = read_era_from_discover_response(&json!({ "error": { "code": -32601 } }));

    assert_eq!(
        verdict,
        EraVerdict::Legacy {
            reason: "the server answered server/discover with error -32601".to_string()
        }
    );
}

#[test]
fn an_error_without_a_code_is_legacy() {
    let verdict = read_era_from_discover_response(&json!({ "error": {} }));

    assert_eq!(
        reason(verdict),
        "the server answered server/discover with error undefined"
    );
}

#[test]
fn anything_that_is_not_a_discover_result_is_a_server_still_expecting_a_handshake() {
    let verdict = read_era_from_discover_response(&json!({ "result": { "tools": [] } }));

    assert_eq!(
        verdict,
        EraVerdict::Legacy {
            reason:
                "the server answered server/discover with something that is not a DiscoverResult"
                    .to_string()
        }
    );
}

#[test]
fn a_discover_result_with_malformed_fields_is_not_a_discover_result() {
    for result in [
        json!({ "supportedVersions": ["2026-07-28", 1], "capabilities": {} }),
        json!({ "supportedVersions": "2026-07-28", "capabilities": {} }),
        json!({ "supportedVersions": ["2026-07-28"] }),
        json!({ "supportedVersions": ["2026-07-28"], "capabilities": [] }),
        json!({ "supportedVersions": ["2026-07-28"], "capabilities": {}, "instructions": 1 }),
        json!({ "supportedVersions": ["2026-07-28"], "capabilities": {}, "instructions": null }),
        json!({ "supportedVersions": ["2026-07-28"], "capabilities": {}, "_meta": "x" }),
        json!({ "supportedVersions": ["2026-07-28"], "capabilities": { "tools": { "listChanged": "yes" } } }),
        json!({ "supportedVersions": ["2026-07-28"], "capabilities": { "logging": true } }),
        json!({ "supportedVersions": ["2026-07-28"], "capabilities": { "experimental": { "x": 1 } } }),
        json!("discover"),
    ] {
        let verdict = read_era_from_discover_response(&json!({ "result": result }));
        assert!(
            matches!(verdict, EraVerdict::Legacy { .. }),
            "{result} was accepted"
        );
    }
}

#[test]
fn vendor_capabilities_survive_into_the_verdict() {
    let result = json!({
        "supportedVersions": ["2025-11-25", "2026-07-28"],
        "capabilities": { "tools": { "listChanged": true }, "vendor": { "x": 1 } },
        "instructions": "be careful",
        "_meta": { "io.modelcontextprotocol/serverInfo": { "name": "cipp", "version": "2.0.0" } },
    });

    let verdict = read_era_from_discover_response(&json!({ "result": result.clone() }));

    assert_eq!(
        verdict,
        EraVerdict::Modern {
            version: "2026-07-28".to_string(),
            discover: result,
        }
    );
}

#[test]
fn a_server_offering_only_revisions_newer_than_any_here_is_reported() {
    let verdict = read_era_from_discover_response(
        &json!({ "error": { "code": -32022, "data": { "supported": ["2027-01-01"] } } }),
    );

    assert_eq!(
        verdict,
        EraVerdict::Incompatible {
            reason: "the server offers 2027-01-01, and this proxy speaks 2026-07-28".to_string()
        }
    );
}

#[test]
fn a_server_asking_for_the_version_already_offered_is_incompatible() {
    let verdict = read_era_from_discover_response(
        &json!({ "error": { "code": -32022, "data": { "supported": ["2026-07-28"] } } }),
    );

    assert_eq!(
        verdict,
        EraVerdict::Incompatible {
            reason:
                "the server asked for protocol version 2026-07-28, which the probe already offered"
                    .to_string()
        }
    );
}

#[test]
fn a_server_that_also_speaks_a_pre_2026_revision_gets_the_handshake() {
    let verdict = read_era_from_discover_response(&json!({
        "error": { "code": -32022, "data": { "supported": ["2027-01-01", "2025-11-25"] } }
    }));

    assert_eq!(
        verdict,
        EraVerdict::Legacy {
            reason: "the server offers no modern revision this proxy speaks (it offers 2027-01-01, 2025-11-25)"
                .to_string()
        }
    );
}

#[test]
fn a_header_or_capability_complaint_is_not_evidence_about_the_era() {
    for code in [-32020, -32021] {
        let verdict = read_era_from_discover_response(&json!({ "error": { "code": code } }));
        assert!(matches!(verdict, EraVerdict::Legacy { .. }));
    }
}

#[test]
fn a_supported_list_that_is_not_a_list_of_revisions_is_not_read_as_one() {
    for data in [
        json!({ "supported": "2026-07-28" }),
        json!({ "supported": [1, 2] }),
        json!(null),
    ] {
        let verdict =
            read_era_from_discover_response(&json!({ "error": { "code": -32022, "data": data } }));
        assert_eq!(
            verdict,
            EraVerdict::Legacy {
                reason: "the server offers no modern revision this proxy speaks".to_string()
            }
        );
    }
}

#[test]
fn a_modern_server_offering_only_revisions_this_proxy_cannot_speak_is_reported() {
    let verdict = read_era_from_discover_response(&json!({
        "result": { "supportedVersions": ["2027-01-01", "2028-01-01"], "capabilities": {} }
    }));

    assert_eq!(
        verdict,
        EraVerdict::Incompatible {
            reason: "the server offers 2027-01-01, 2028-01-01, and this proxy speaks 2026-07-28"
                .to_string()
        }
    );
}
