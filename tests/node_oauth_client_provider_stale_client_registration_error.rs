use rust_mcp_remote::node_oauth_client_provider::{OAuthError, stale_client_registration_error};
use serde_json::json;

#[test]
fn maps_invalid_client_with_its_description() {
    assert_eq!(
        stale_client_registration_error(
            &json!({"error": "invalid_client", "error_description": "gone"})
        ),
        Some(OAuthError {
            code: "invalid_client".to_string(),
            message: "gone".to_string(),
        })
    );
}

#[test]
fn maps_unauthorized_client_with_the_default_message() {
    assert_eq!(
        stale_client_registration_error(
            &json!({"error": "unauthorized_client", "error_description": 7})
        ),
        Some(OAuthError {
            code: "unauthorized_client".to_string(),
            message: "Cached OAuth client registration is no longer valid".to_string(),
        })
    );
}

#[test]
fn ignores_other_errors() {
    assert_eq!(
        stale_client_registration_error(&json!({"error": "invalid_grant"})),
        None
    );
}

#[test]
fn ignores_values_that_are_not_objects() {
    assert_eq!(stale_client_registration_error(&json!(null)), None);
    assert_eq!(
        stale_client_registration_error(&json!("invalid_client")),
        None
    );
    assert_eq!(
        stale_client_registration_error(&json!(["invalid_client"])),
        None
    );
}
