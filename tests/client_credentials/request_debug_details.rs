use rust_mcp_remote::client_credentials::client_credentials_request_debug_details;
use serde_json::json;

#[test]
fn names_every_field_in_the_order_the_typescript_gives_them() {
    let details = client_credentials_request_debug_details(
        "https://auth.example.com/token",
        "client_secret_basic",
        Some("read write"),
        Some("https://mcp.example.com/"),
    );

    assert_eq!(
        details.to_string(),
        r#"{"tokenEndpoint":"https://auth.example.com/token","authMethod":"client_secret_basic","scope":"read write","resource":"https://mcp.example.com/"}"#
    );
}

#[test]
fn leaves_out_a_missing_scope_and_resource() {
    let details = client_credentials_request_debug_details(
        "https://auth.example.com/token",
        "client_secret_post",
        None,
        None,
    );

    assert_eq!(
        details,
        json!({
            "tokenEndpoint": "https://auth.example.com/token",
            "authMethod": "client_secret_post",
        })
    );
}

#[test]
fn keeps_an_empty_scope() {
    let details = client_credentials_request_debug_details(
        "https://auth.example.com/token",
        "client_secret_post",
        Some(""),
        None,
    );

    assert_eq!(details.get("scope"), Some(&json!("")));
}
