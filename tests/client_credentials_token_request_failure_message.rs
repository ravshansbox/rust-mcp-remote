use rust_mcp_remote::client_credentials::token_request_failure_message;
use serde_json::json;

#[test]
fn prefers_error_description() {
    let body =
        json!({"error": "invalid_client", "error_description": "Client authentication failed"});
    assert_eq!(
        token_request_failure_message(401, Some(&body)),
        "The client_credentials token request failed (HTTP 401): Client authentication failed"
    );
}

#[test]
fn falls_back_to_error() {
    let body = json!({"error": "invalid_scope"});
    assert_eq!(
        token_request_failure_message(400, Some(&body)),
        "The client_credentials token request failed (HTTP 400): invalid_scope"
    );
}

#[test]
fn uses_unknown_error_without_a_body() {
    assert_eq!(
        token_request_failure_message(500, None),
        "The client_credentials token request failed (HTTP 500): unknown error"
    );
}

#[test]
fn uses_unknown_error_when_neither_field_is_present() {
    let body = json!({"message": "nope"});
    assert_eq!(
        token_request_failure_message(502, Some(&body)),
        "The client_credentials token request failed (HTTP 502): unknown error"
    );
}

#[test]
fn keeps_an_empty_error_description() {
    let body = json!({"error": "invalid_client", "error_description": ""});
    assert_eq!(
        token_request_failure_message(401, Some(&body)),
        "The client_credentials token request failed (HTTP 401): "
    );
}

#[test]
fn skips_a_null_error_description() {
    let body = json!({"error": "invalid_client", "error_description": null});
    assert_eq!(
        token_request_failure_message(401, Some(&body)),
        "The client_credentials token request failed (HTTP 401): invalid_client"
    );
}

#[test]
fn cuts_the_detail_to_500_characters() {
    let body = json!({"error_description": "x".repeat(600)});
    assert_eq!(
        token_request_failure_message(400, Some(&body)),
        format!(
            "The client_credentials token request failed (HTTP 400): {}",
            "x".repeat(500)
        )
    );
}
