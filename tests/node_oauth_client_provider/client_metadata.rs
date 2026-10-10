use rust_mcp_remote::node_oauth_client_provider::{NodeOAuthClientProvider, OAuthProviderOptions};
use serde_json::json;

fn options() -> OAuthProviderOptions {
    OAuthProviderOptions {
        server_url: "https://auth.example.com".to_string(),
        callback_port: 3334,
        host: "localhost".to_string(),
        server_url_hash: "abc123".to_string(),
        ..Default::default()
    }
}

#[test]
fn client_metadata_uses_defaults_and_the_fallback_scope() {
    let provider = NodeOAuthClientProvider::new(options()).unwrap();
    assert_eq!(
        provider.client_metadata(),
        json!({
            "redirect_uris": ["http://localhost:3334/oauth/callback"],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_name": "MCP CLI Client",
            "client_uri": "https://github.com/modelcontextprotocol/mcp-cli",
            "software_id": "2e6dc280-f3c3-4e01-99a7-8181dbd1d23d",
            "software_version": provider.software_version,
            "scope": "openid email profile",
        })
    );
}

#[test]
fn client_metadata_reads_server_metadata_for_auth_method_and_scope() {
    let provider = NodeOAuthClientProvider::new(OAuthProviderOptions {
        authorization_server_metadata: Some(json!({
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
            "scopes_supported": ["read", "write"],
        })),
        ..options()
    })
    .unwrap();
    let metadata = provider.client_metadata();
    assert_eq!(metadata["token_endpoint_auth_method"], "client_secret_post");
    assert_eq!(metadata["scope"], "read write");
}

#[test]
fn client_metadata_prefers_the_www_authenticate_scope() {
    let provider = NodeOAuthClientProvider::new(OAuthProviderOptions {
        www_authenticate_scope: Some("mcp:tools".to_string()),
        protected_resource_metadata: Some(json!({ "scopes_supported": ["other"] })),
        ..options()
    })
    .unwrap();
    assert_eq!(provider.effective_scope(), "mcp:tools");
    assert_eq!(provider.client_metadata()["scope"], "mcp:tools");
}

#[test]
fn client_metadata_reads_the_scope_from_client_info() {
    let mut provider = NodeOAuthClientProvider::new(options()).unwrap();
    provider.client_info = Some(json!({ "client_id": "abc", "scope": "registered" }));
    assert_eq!(provider.effective_scope(), "registered");
}

#[test]
fn client_metadata_for_client_credentials_has_no_redirect_and_no_scope() {
    let provider = NodeOAuthClientProvider::new(OAuthProviderOptions {
        use_client_credentials: Some(true),
        token_endpoint: Some("https://tokens.example.com/oauth/token".to_string()),
        ..options()
    })
    .unwrap();
    let metadata = provider.client_metadata();
    assert_eq!(metadata["redirect_uris"], json!([]));
    assert_eq!(metadata["grant_types"], json!(["client_credentials"]));
    assert!(metadata.get("scope").is_none());
}

#[test]
fn client_metadata_for_device_code_uses_the_device_grant() {
    let provider = NodeOAuthClientProvider::new(OAuthProviderOptions {
        use_device_code: Some(true),
        ..options()
    })
    .unwrap();
    assert_eq!(
        provider.grant_types(),
        vec![
            "urn:ietf:params:oauth:grant-type:device_code",
            "refresh_token"
        ]
    );
}

#[test]
fn client_metadata_merges_static_metadata() {
    let provider = NodeOAuthClientProvider::new(OAuthProviderOptions {
        static_oauth_client_metadata: Some(json!({ "client_name": "Custom", "scope": "custom" })),
        ..options()
    })
    .unwrap();
    let metadata = provider.client_metadata();
    assert_eq!(metadata["client_name"], "Custom");
    assert_eq!(metadata["scope"], "custom");
}
