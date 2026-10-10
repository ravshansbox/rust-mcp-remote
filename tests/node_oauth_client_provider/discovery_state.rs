use rust_mcp_remote::node_oauth_client_provider::{
    discovery_state, has_explicit_token_endpoint, redirect_url,
};
use serde_json::json;

#[test]
fn explicit_token_endpoint_needs_client_credentials_and_an_endpoint() {
    assert!(has_explicit_token_endpoint(
        true,
        Some("https://auth.example.com/token")
    ));
    assert!(!has_explicit_token_endpoint(
        false,
        Some("https://auth.example.com/token")
    ));
    assert!(!has_explicit_token_endpoint(true, Some("")));
    assert!(!has_explicit_token_endpoint(true, None));
}

#[test]
fn redirect_url_is_built_without_an_explicit_token_endpoint() {
    assert_eq!(
        redirect_url(false, "localhost", 3334, "/oauth/callback"),
        Some("http://localhost:3334/oauth/callback".to_string())
    );
}

#[test]
fn redirect_url_is_absent_with_an_explicit_token_endpoint() {
    assert_eq!(
        redirect_url(true, "localhost", 3334, "/oauth/callback"),
        None
    );
}

#[test]
fn discovery_state_is_absent_without_an_explicit_token_endpoint() {
    assert_eq!(
        discovery_state(
            false,
            Some("https://auth.example.com/token"),
            "https://mcp.example.com/mcp"
        ),
        None
    );
}

#[test]
fn discovery_state_describes_the_token_endpoint() {
    assert_eq!(
        discovery_state(
            true,
            Some("https://auth.example.com:8443/oauth/token"),
            "https://mcp.example.com/mcp"
        ),
        Some(json!({
            "authorizationServerUrl": "https://auth.example.com:8443",
            "authorizationServerMetadata": {
                "issuer": "https://auth.example.com:8443",
                "token_endpoint": "https://auth.example.com:8443/oauth/token",
                "grant_types_supported": ["client_credentials"],
            },
            "resourceMetadata": {
                "resource": "https://mcp.example.com/mcp",
                "authorization_servers": ["https://auth.example.com:8443"],
            },
        }))
    );
}
